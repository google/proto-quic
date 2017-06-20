#!/usr/bin/python
# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Prints the size of each given file and optionally computes the size of
   libchrome.so without the dependencies added for building with android NDK.
   Also breaks down the contents of the APK to determine the installed size
   and assign size contributions to different classes of file.
"""

import argparse
import collections
from contextlib import contextmanager
import json
import logging
import operator
import os
import re
import struct
import sys
import tempfile
import zipfile
import zlib

from binary_size import apk_downloader
import devil_chromium
from devil.android.sdk import build_tools
from devil.utils import cmd_helper
from devil.utils import lazy
import method_count
from pylib import constants
from pylib.constants import host_paths

_AAPT_PATH = lazy.WeakConstant(lambda: build_tools.GetPath('aapt'))
_GRIT_PATH = os.path.join(host_paths.DIR_SOURCE_ROOT, 'tools', 'grit')
_BUILD_UTILS_PATH = os.path.join(
    host_paths.DIR_SOURCE_ROOT, 'build', 'android', 'gyp')
_APK_PATCH_SIZE_ESTIMATOR_PATH = os.path.join(
    host_paths.DIR_SOURCE_ROOT, 'third_party', 'apk-patch-size-estimator')

# Prepend the grit module from the source tree so it takes precedence over other
# grit versions that might present in the search path.
with host_paths.SysPath(_GRIT_PATH, 0):
  from grit.format import data_pack # pylint: disable=import-error

with host_paths.SysPath(host_paths.BUILD_COMMON_PATH):
  import perf_tests_results_helper # pylint: disable=import-error

with host_paths.SysPath(_BUILD_UTILS_PATH, 0):
  from util import build_utils # pylint: disable=import-error

with host_paths.SysPath(_APK_PATCH_SIZE_ESTIMATOR_PATH):
  import apk_patch_size_estimator # pylint: disable=import-error


# Python had a bug in zipinfo parsing that triggers on ChromeModern.apk
# https://bugs.python.org/issue14315
def _PatchedDecodeExtra(self):
  # Try to decode the extra field.
  extra = self.extra
  unpack = struct.unpack
  while len(extra) >= 4:
    tp, ln = unpack('<HH', extra[:4])
    if tp == 1:
      if ln >= 24:
        counts = unpack('<QQQ', extra[4:28])
      elif ln == 16:
        counts = unpack('<QQ', extra[4:20])
      elif ln == 8:
        counts = unpack('<Q', extra[4:12])
      elif ln == 0:
        counts = ()
      else:
        raise RuntimeError, "Corrupt extra field %s"%(ln,)

      idx = 0

      # ZIP64 extension (large files and/or large archives)
      if self.file_size in (0xffffffffffffffffL, 0xffffffffL):
        self.file_size = counts[idx]
        idx += 1

      if self.compress_size == 0xFFFFFFFFL:
        self.compress_size = counts[idx]
        idx += 1

      if self.header_offset == 0xffffffffL:
        self.header_offset = counts[idx]
        idx += 1

    extra = extra[ln + 4:]

zipfile.ZipInfo._decodeExtra = (  # pylint: disable=protected-access
    _PatchedDecodeExtra)

# Captures an entire config from aapt output.
_AAPT_CONFIG_PATTERN = r'config %s:(.*?)config [a-zA-Z-]+:'
# Matches string resource entries from aapt output.
_AAPT_ENTRY_RE = re.compile(
    r'resource (?P<id>\w{10}) [\w\.]+:string/.*?"(?P<val>.+?)"', re.DOTALL)
_BASE_CHART = {
    'format_version': '0.1',
    'benchmark_name': 'resource_sizes',
    'benchmark_description': 'APK resource size information.',
    'trace_rerun_options': [],
    'charts': {}
}
_DUMP_STATIC_INITIALIZERS_PATH = os.path.join(
    host_paths.DIR_SOURCE_ROOT, 'tools', 'linux', 'dump-static-initializers.py')
# Pragma exists when enable_resource_whitelist_generation=true.
_RC_HEADER_RE = re.compile(
    r'^#define (?P<name>\w+) (?:_Pragma\(.*?\) )?(?P<id>\d+)$')
_RE_NON_LANGUAGE_PAK = re.compile(r'^assets/.*(resources|percent)\.pak$')
_RE_COMPRESSED_LANGUAGE_PAK = re.compile(
    r'\.lpak$|^assets/(?!stored-locales/).*(?!resources|percent)\.pak$')
_RE_STORED_LANGUAGE_PAK = re.compile(r'^assets/stored-locales/.*\.pak$')
_READELF_SIZES_METRICS = {
  'text': ['.text'],
  'data': ['.data', '.rodata', '.data.rel.ro', '.data.rel.ro.local'],
  'relocations': ['.rel.dyn', '.rel.plt', '.rela.dyn', '.rela.plt'],
  'unwind': ['.ARM.extab', '.ARM.exidx', '.eh_frame', '.eh_frame_hdr',],
  'symbols': ['.dynsym', '.dynstr', '.dynamic', '.shstrtab', '.got', '.plt',
              '.got.plt', '.hash'],
  'bss': ['.bss'],
  'other': ['.init_array', '.fini_array', '.comment', '.note.gnu.gold-version',
            '.ARM.attributes', '.note.gnu.build-id', '.gnu.version',
            '.gnu.version_d', '.gnu.version_r', '.interp', '.gcc_except_table']
}


def _RunReadelf(so_path, options, tools_prefix=''):
  return cmd_helper.GetCmdOutput(
      [tools_prefix + 'readelf'] + options + [so_path])


def _ExtractMainLibSectionSizesFromApk(apk_path, main_lib_path, tools_prefix):
  with Unzip(apk_path, filename=main_lib_path) as extracted_lib_path:
    grouped_section_sizes = collections.defaultdict(int)
    section_sizes = _CreateSectionNameSizeMap(extracted_lib_path, tools_prefix)
    for group_name, section_names in _READELF_SIZES_METRICS.iteritems():
      for section_name in section_names:
        if section_name in section_sizes:
          grouped_section_sizes[group_name] += section_sizes.pop(section_name)

    # Group any unknown section headers into the "other" group.
    for section_header, section_size in section_sizes.iteritems():
      print "Unknown elf section header:", section_header
      grouped_section_sizes['other'] += section_size

    return grouped_section_sizes


def _CreateSectionNameSizeMap(so_path, tools_prefix):
  stdout = _RunReadelf(so_path, ['-S', '--wide'], tools_prefix)
  section_sizes = {}
  # Matches  [ 2] .hash HASH 00000000006681f0 0001f0 003154 04   A  3   0  8
  for match in re.finditer(r'\[[\s\d]+\] (\..*)$', stdout, re.MULTILINE):
    items = match.group(1).split()
    section_sizes[items[0]] = int(items[4], 16)

  return section_sizes


def _ParseLibBuildId(so_path, tools_prefix):
  """Returns the Build ID of the given native library."""
  stdout = _RunReadelf(so_path, ['-n'], tools_prefix)
  match = re.search(r'Build ID: (\w+)', stdout)
  return match.group(1) if match else None


def _ParseManifestAttributes(apk_path):
  # Check if the manifest specifies whether or not to extract native libs.
  skip_extract_lib = False
  output = cmd_helper.GetCmdOutput([
      _AAPT_PATH.read(), 'd', 'xmltree', apk_path, 'AndroidManifest.xml'])
  m = re.search(r'extractNativeLibs\(.*\)=\(.*\)(\w)', output)
  if m:
    skip_extract_lib = not bool(int(m.group(1)))

  # Dex decompression overhead varies by Android version.
  m = re.search(r'android:minSdkVersion\(\w+\)=\(type \w+\)(\w+)\n', output)
  sdk_version = int(m.group(1), 16)
  # Pre-L: Dalvik - .odex file is simply decompressed/optimized dex file (~1x).
  # L, M: ART - .odex file is compiled version of the dex file (~3x).
  # N: ART - Uses Dalvik-like JIT for normal apps (~1x), full compilation for
  #    shared apps (~3x).
  if sdk_version < 21:
    dex_multiplier = 1
  elif sdk_version < 24:
    dex_multiplier = 3
  elif 'Monochrome' in apk_path or 'WebView' in apk_path:
    dex_multiplier = 3
  else:
    dex_multiplier = 1

  return dex_multiplier, skip_extract_lib


def CountStaticInitializers(so_path, tools_prefix):
  # Static initializers expected in official builds. Note that this list is
  # built using 'nm' on libchrome.so which results from a GCC official build
  # (i.e. Clang is not supported currently).
  def get_elf_section_size(readelf_stdout, section_name):
    # Matches: .ctors PROGBITS 000000000516add0 5169dd0 000010 00 WA 0 0 8
    match = re.search(r'\.%s.*$' % re.escape(section_name),
                      readelf_stdout, re.MULTILINE)
    if not match:
      return (False, -1)
    size_str = re.split(r'\W+', match.group(0))[5]
    return (True, int(size_str, 16))

  # Find the number of files with at least one static initializer.
  # First determine if we're 32 or 64 bit
  stdout = _RunReadelf(so_path, ['-h'], tools_prefix)
  elf_class_line = re.search('Class:.*$', stdout, re.MULTILINE).group(0)
  elf_class = re.split(r'\W+', elf_class_line)[1]
  if elf_class == 'ELF32':
    word_size = 4
  else:
    word_size = 8

  # Then find the number of files with global static initializers.
  # NOTE: this is very implementation-specific and makes assumptions
  # about how compiler and linker implement global static initializers.
  si_count = 0
  stdout = _RunReadelf(so_path, ['-SW'], tools_prefix)
  has_init_array, init_array_size = get_elf_section_size(stdout, 'init_array')
  if has_init_array:
    si_count = init_array_size / word_size
  si_count = max(si_count, 0)
  return si_count


def GetStaticInitializers(so_path, tools_prefix):
  output = cmd_helper.GetCmdOutput([_DUMP_STATIC_INITIALIZERS_PATH, '-d',
                                    so_path, '-t', tools_prefix])
  summary = re.search(r'Found \d+ static initializers in (\d+) files.', output)
  return output.splitlines()[:-1], int(summary.group(1))


def _NormalizeLanguagePaks(translations, normalized_apk_size, factor):
  english_pak = translations.FindByPattern(r'.*/en[-_][Uu][Ss]\.l?pak')
  num_translations = translations.GetNumEntries()
  if english_pak:
    normalized_apk_size -= translations.ComputeZippedSize()
    normalized_apk_size += int(
        english_pak.compress_size * num_translations * factor)
  return normalized_apk_size


def _NormalizeResourcesArsc(apk_path):
  """Estimates the expected overhead of untranslated strings in resources.arsc.

  See http://crbug.com/677966 for why this is necessary.
  """
  aapt_output = _RunAaptDumpResources(apk_path)

  # en-rUS is in the default config and may be cluttered with non-translatable
  # strings, so en-rGB is a better baseline for finding missing translations.
  en_strings = _CreateResourceIdValueMap(aapt_output, 'en-rGB')
  fr_strings = _CreateResourceIdValueMap(aapt_output, 'fr')

  # Chrome supports 44 locales (en-US and en-GB will never be translated).
  # This can be changed to |translations.GetNumEntries()| when Chrome and
  # WebView support the same set of locales (http://crbug.com/369218).
  config_count = 42

  size = 0
  for res_id, string_val in en_strings.iteritems():
    if string_val == fr_strings[res_id]:
      string_size = len(string_val)
      # 7 bytes is the per-entry overhead (not specific to any string). See
      # https://android.googlesource.com/platform/frameworks/base.git/+/android-4.2.2_r1/tools/aapt/StringPool.cpp#414.
      # The 1.5 factor was determined experimentally and is meant to account for
      # other languages generally having longer strings than english.
      size += config_count * (7 + string_size * 1.5)

  return size


def _CreateResourceIdValueMap(aapt_output, lang):
  """Return a map of resource ids to string values for the given |lang|."""
  config_re = _AAPT_CONFIG_PATTERN % lang
  return {entry.group('id'): entry.group('val')
          for config_section in re.finditer(config_re, aapt_output, re.DOTALL)
          for entry in re.finditer(_AAPT_ENTRY_RE, config_section.group(0))}


def _RunAaptDumpResources(apk_path):
  cmd = [_AAPT_PATH.read(), 'dump', '--values', 'resources', apk_path]
  status, output = cmd_helper.GetCmdStatusAndOutput(cmd)
  if status != 0:
    raise Exception('Failed running aapt command: "%s" with output "%s".' %
                    (' '.join(cmd), output))
  return output


def ReportPerfResult(chart_data, graph_title, trace_title, value, units,
                     improvement_direction='down', important=True):
  """Outputs test results in correct format.

  If chart_data is None, it outputs data in old format. If chart_data is a
  dictionary, formats in chartjson format. If any other format defaults to
  old format.
  """
  if chart_data and isinstance(chart_data, dict):
    chart_data['charts'].setdefault(graph_title, {})
    chart_data['charts'][graph_title][trace_title] = {
        'type': 'scalar',
        'value': value,
        'units': units,
        'improvement_direction': improvement_direction,
        'important': important
    }
  else:
    perf_tests_results_helper.PrintPerfResult(
        graph_title, trace_title, [value], units)


class _FileGroup(object):
  """Represents a category that apk files can fall into."""

  def __init__(self, name):
    self.name = name
    self._zip_infos = []
    self._extracted_multipliers = []

  def AddZipInfo(self, zip_info, extracted_multiplier=0):
    self._zip_infos.append(zip_info)
    self._extracted_multipliers.append(extracted_multiplier)

  def AllEntries(self):
    return iter(self._zip_infos)

  def GetNumEntries(self):
    return len(self._zip_infos)

  def FindByPattern(self, pattern):
    return next((i for i in self._zip_infos if re.match(pattern, i.filename)),
                None)

  def FindLargest(self):
    if not self._zip_infos:
      return None
    return max(self._zip_infos, key=lambda i: i.file_size)

  def ComputeZippedSize(self):
    return sum(i.compress_size for i in self._zip_infos)

  def ComputeUncompressedSize(self):
    return sum(i.file_size for i in self._zip_infos)

  def ComputeExtractedSize(self):
    ret = 0
    for zi, multiplier in zip(self._zip_infos, self._extracted_multipliers):
      ret += zi.file_size * multiplier
    return ret

  def ComputeInstallSize(self):
    return self.ComputeExtractedSize() + self.ComputeZippedSize()


def PrintApkAnalysis(apk_filename, tools_prefix, chartjson=None):
  """Analyse APK to determine size contributions of different file classes."""
  file_groups = []

  def make_group(name):
    group = _FileGroup(name)
    file_groups.append(group)
    return group

  native_code = make_group('Native code')
  java_code = make_group('Java code')
  native_resources_no_translations = make_group('Native resources (no l10n)')
  translations = make_group('Native resources (l10n)')
  stored_translations = make_group('Native resources stored (l10n)')
  icu_data = make_group('ICU (i18n library) data')
  v8_snapshots = make_group('V8 Snapshots')
  png_drawables = make_group('PNG drawables')
  res_directory = make_group('Non-compiled Android resources')
  arsc = make_group('Compiled Android resources')
  metadata = make_group('Package metadata')
  unknown = make_group('Unknown files')
  notices = make_group('licenses.notice file')

  apk = zipfile.ZipFile(apk_filename, 'r')
  try:
    apk_contents = apk.infolist()
  finally:
    apk.close()

  dex_multiplier, skip_extract_lib = _ParseManifestAttributes(apk_filename)
  total_apk_size = os.path.getsize(apk_filename)
  apk_basename = os.path.basename(apk_filename)
  for member in apk_contents:
    filename = member.filename
    if filename.endswith('/'):
      continue
    if filename.endswith('.so'):
      should_extract_lib = not (skip_extract_lib or 'crazy' in filename)
      native_code.AddZipInfo(
          member, extracted_multiplier=int(should_extract_lib))
    elif filename.endswith('.dex'):
      java_code.AddZipInfo(member, extracted_multiplier=dex_multiplier)
    elif re.search(_RE_NON_LANGUAGE_PAK, filename):
      native_resources_no_translations.AddZipInfo(member)
    elif re.search(_RE_COMPRESSED_LANGUAGE_PAK, filename):
      translations.AddZipInfo(
          member,
          extracted_multiplier=int('en_' in filename or 'en-' in filename))
    elif re.search(_RE_STORED_LANGUAGE_PAK, filename):
      stored_translations.AddZipInfo(member)
    elif filename == 'assets/icudtl.dat':
      icu_data.AddZipInfo(member)
    elif filename.endswith('.bin'):
      v8_snapshots.AddZipInfo(member)
    elif filename.endswith('.png') or filename.endswith('.webp'):
      png_drawables.AddZipInfo(member)
    elif filename.startswith('res/'):
      res_directory.AddZipInfo(member)
    elif filename.endswith('.arsc'):
      arsc.AddZipInfo(member)
    elif filename.startswith('META-INF') or filename == 'AndroidManifest.xml':
      metadata.AddZipInfo(member)
    elif filename.endswith('.notice'):
      notices.AddZipInfo(member)
    else:
      unknown.AddZipInfo(member)

  total_install_size = total_apk_size

  for group in file_groups:
    install_size = group.ComputeInstallSize()
    total_install_size += group.ComputeExtractedSize()

    ReportPerfResult(chartjson, apk_basename + '_Breakdown',
                     group.name + ' size', group.ComputeZippedSize(), 'bytes')
    ReportPerfResult(chartjson, apk_basename + '_InstallBreakdown',
                     group.name + ' size', install_size, 'bytes')
    ReportPerfResult(chartjson, apk_basename + '_Uncompressed',
                     group.name + ' size', group.ComputeUncompressedSize(),
                     'bytes')

  ReportPerfResult(chartjson, apk_basename + '_InstallSize', 'APK size',
                   total_apk_size, 'bytes')
  ReportPerfResult(chartjson, apk_basename + '_InstallSize',
                   'Estimated installed size', total_install_size, 'bytes')
  transfer_size = _CalculateCompressedSize(apk_filename)
  ReportPerfResult(chartjson, apk_basename + '_TransferSize',
                   'Transfer size (deflate)', transfer_size, 'bytes')

  # Size of main dex vs remaining.
  main_dex_info = java_code.FindByPattern('classes.dex')
  if main_dex_info:
    main_dex_size = main_dex_info.file_size
    ReportPerfResult(chartjson, apk_basename + '_Specifics',
                     'main dex size', main_dex_size, 'bytes')
    secondary_size = java_code.ComputeUncompressedSize() - main_dex_size
    ReportPerfResult(chartjson, apk_basename + '_Specifics',
                     'secondary dex size', secondary_size, 'bytes')

  # Size of main .so vs remaining.
  main_lib_info = native_code.FindLargest()
  if main_lib_info:
    main_lib_size = main_lib_info.file_size
    ReportPerfResult(chartjson, apk_basename + '_Specifics',
                     'main lib size', main_lib_size, 'bytes')
    secondary_size = native_code.ComputeUncompressedSize() - main_lib_size
    ReportPerfResult(chartjson, apk_basename + '_Specifics',
                     'other lib size', secondary_size, 'bytes')

    main_lib_section_sizes = _ExtractMainLibSectionSizesFromApk(
        apk_filename, main_lib_info.filename, tools_prefix)
    for metric_name, size in main_lib_section_sizes.iteritems():
      ReportPerfResult(chartjson, apk_basename + '_MainLibInfo',
                       metric_name, size, 'bytes')

  # Main metric that we want to monitor for jumps.
  normalized_apk_size = total_apk_size
  # Always look at uncompressed .dex & .so.
  normalized_apk_size -= java_code.ComputeZippedSize()
  normalized_apk_size += java_code.ComputeUncompressedSize()
  normalized_apk_size -= native_code.ComputeZippedSize()
  normalized_apk_size += native_code.ComputeUncompressedSize()
  # Avoid noise caused when strings change and translations haven't yet been
  # updated.
  num_translations = translations.GetNumEntries()
  if num_translations > 1:
    # Multipliers found by looking at MonochromePublic.apk and seeing how much
    # smaller en-US.pak is relative to the average locale.pak.
    normalized_apk_size = _NormalizeLanguagePaks(
        translations, normalized_apk_size, 1.17)
    normalized_apk_size = _NormalizeLanguagePaks(
        stored_translations, normalized_apk_size, 1.43)
    normalized_apk_size += int(_NormalizeResourcesArsc(apk_filename))

  ReportPerfResult(chartjson, apk_basename + '_Specifics',
                   'normalized apk size', normalized_apk_size, 'bytes')

  ReportPerfResult(chartjson, apk_basename + '_Specifics',
                   'file count', len(apk_contents), 'zip entries')

  for info in unknown.AllEntries():
    print 'Unknown entry:', info.filename, info.compress_size


def IsPakFileName(file_name):
  """Returns whether the given file name ends with .pak or .lpak."""
  return file_name.endswith('.pak') or file_name.endswith('.lpak')


def PrintPakAnalysis(apk_filename, min_pak_resource_size):
  """Print sizes of all resources in all pak files in |apk_filename|."""
  print
  print 'Analyzing pak files in %s...' % apk_filename

  # A structure for holding details about a pak file.
  Pak = collections.namedtuple(
      'Pak', ['filename', 'compress_size', 'file_size', 'resources'])

  # Build a list of Pak objets for each pak file.
  paks = []
  apk = zipfile.ZipFile(apk_filename, 'r')
  try:
    for i in (x for x in apk.infolist() if IsPakFileName(x.filename)):
      with tempfile.NamedTemporaryFile() as f:
        f.write(apk.read(i.filename))
        f.flush()
        paks.append(Pak(i.filename, i.compress_size, i.file_size,
                        data_pack.DataPack.ReadDataPack(f.name).resources))
  finally:
    apk.close()

  # Output the overall pak file summary.
  total_files = len(paks)
  total_compress_size = sum(pak.compress_size for pak in paks)
  total_file_size = sum(pak.file_size for pak in paks)
  print 'Total pak files: %d' % total_files
  print 'Total compressed size: %s' % _FormatBytes(total_compress_size)
  print 'Total uncompressed size: %s' % _FormatBytes(total_file_size)
  print

  if not paks:
    return

  # Output the table of details about all pak files.
  print '%25s%11s%21s%21s' % (
      'FILENAME', 'RESOURCES', 'COMPRESSED SIZE', 'UNCOMPRESSED SIZE')
  for pak in sorted(paks, key=operator.attrgetter('file_size'), reverse=True):
    print '%25s %10s %12s %6.2f%% %12s %6.2f%%' % (
        pak.filename,
        len(pak.resources),
        _FormatBytes(pak.compress_size),
        100.0 * pak.compress_size / total_compress_size,
        _FormatBytes(pak.file_size),
        100.0 * pak.file_size / total_file_size)

  print
  print 'Analyzing pak resources in %s...' % apk_filename

  # Calculate aggregate stats about resources across pak files.
  resource_count_map = collections.defaultdict(int)
  resource_size_map = collections.defaultdict(int)
  resource_overhead_bytes = 6
  for pak in paks:
    for r in pak.resources:
      resource_count_map[r] += 1
      resource_size_map[r] += len(pak.resources[r]) + resource_overhead_bytes

  # Output the overall resource summary.
  total_resource_size = sum(resource_size_map.values())
  total_resource_count = len(resource_count_map)
  assert total_resource_size <= total_file_size
  print 'Total pak resources: %s' % total_resource_count
  print 'Total uncompressed resource size: %s' % _FormatBytes(
      total_resource_size)
  print

  resource_id_name_map, resources_id_header_map = _AnnotatePakResources()

  # Output the table of details about all resources across pak files.
  print
  print '%56s %5s %17s' % ('RESOURCE', 'COUNT', 'UNCOMPRESSED SIZE')
  for i in sorted(resource_size_map, key=resource_size_map.get,
                  reverse=True):
    if resource_size_map[i] < min_pak_resource_size:
      break

    print '%56s %5s %9s %6.2f%%' % (
        resource_id_name_map.get(i, i),
        resource_count_map[i],
        _FormatBytes(resource_size_map[i]),
        100.0 * resource_size_map[i] / total_resource_size)

  # Print breakdown on a per-grd file basis.
  size_by_header = collections.defaultdict(int)
  for resid, size in resource_size_map.iteritems():
    size_by_header[resources_id_header_map.get(resid, 'unknown')] += size

  print
  print '%80s %17s' % ('HEADER', 'UNCOMPRESSED SIZE')
  for header in sorted(size_by_header, key=size_by_header.get, reverse=True):
    if size_by_header[header] < min_pak_resource_size:
      break

    print '%80s %9s %6.2f%%' % (
        header,
        _FormatBytes(size_by_header[header]),
        100.0 * size_by_header[header] / total_resource_size)


def _AnnotatePakResources():
  """Returns a pair of maps: id_name_map, id_header_map."""
  out_dir = constants.GetOutDirectory()
  assert os.path.isdir(out_dir), 'Failed to locate out dir at %s' % out_dir
  print 'Looking at resources in: %s' % out_dir

  grit_headers = []
  for root, _, files in os.walk(out_dir):
    if root.endswith('grit'):
      grit_headers += [os.path.join(root, f) for f in files if f.endswith('.h')]
  assert grit_headers, 'Failed to find grit headers in %s' % out_dir

  id_name_map = {}
  id_header_map = {}
  for header in grit_headers:
    with open(header, 'r') as f:
      for line in f.readlines():
        m = _RC_HEADER_RE.match(line.strip())
        if m:
          i = int(m.group('id'))
          name = m.group('name')
          if i in id_name_map and name != id_name_map[i]:
            print 'WARNING: Resource ID conflict %s (%s vs %s)' % (
                i, id_name_map[i], name)
          id_name_map[i] = name
          id_header_map[i] = os.path.relpath(header, out_dir)
  return id_name_map, id_header_map


def _PrintStaticInitializersCountFromApk(apk_filename, tools_prefix,
                                         dump_sis, chartjson=None):
  with zipfile.ZipFile(apk_filename) as z:
    so_files = [f for f in z.infolist()
                if f.filename.endswith('.so') and f.file_size > 0]
  # Skip checking static initializers for 32 bit .so files when 64 bit .so files
  # are present since the 32 bit versions will be checked by bots that only
  # build the 32 bit version. This avoids the complexity of finding 32 bit .so
  # files in the output directory in 64 bit builds.
  has_64 = any('64' in f.filename for f in so_files)
  files_to_check = [f for f in so_files if not has_64 or '64' in f.filename]
  out_dir = constants.GetOutDirectory()
  si_count = 0
  for so_info in files_to_check:
    lib_name = os.path.basename(so_info.filename).replace('crazy.', '')
    unstripped_path = os.path.join(out_dir, 'lib.unstripped', lib_name)
    if os.path.exists(unstripped_path):
      si_count += _PrintStaticInitializersCount(
          apk_filename, so_info.filename, unstripped_path, tools_prefix,
          dump_sis)
    else:
      raise Exception('Unstripped .so not found. Looked here: %s',
                      unstripped_path)
  ReportPerfResult(chartjson, 'StaticInitializersCount', 'count', si_count,
                   'count')


def _PrintStaticInitializersCount(apk_path, apk_so_name, so_with_symbols_path,
                                  tools_prefix, dump_sis):
  """Counts the number of static initializers in the given shared library.

     Args:
      apk_path: Path to the apk.
      apk_so_name: Name of the so.
      so_with_symbols_path: Path to the unstripped libchrome.so file.
      tools_prefix: Prefix for arch-specific version of binary utility tools.
      dump_sis: Whether or not to run dump-static-initializers.py and print
          the list of static initializers to stdout.
     Returns:
       The number of static initializers found.
  """
  # GetStaticInitializers uses get-static-initializers.py to get a list of all
  # static initializers. This does not work on all archs (particularly arm).
  # This mostly copies infra/scripts/legacy/scripts/slave/chromium/sizes.py.
  print 'Finding static initializers in %s (can take a minute)' % apk_so_name
  with Unzip(apk_path, filename=apk_so_name) as unzipped_so:
    _VerifyLibBuildIdsMatch(tools_prefix, unzipped_so, so_with_symbols_path)
    readelf_si_count = CountStaticInitializers(unzipped_so, tools_prefix)
  if dump_sis:
    sis, dump_si_count = GetStaticInitializers(
        so_with_symbols_path, tools_prefix)
    print ('Found %s files with static initializers using readelf\n'
           'Found %s files with static initializers using '
           'dump-static-initializers') % (readelf_si_count, dump_si_count)
    print '\n'.join(sis)

  return readelf_si_count


def _FormatBytes(byts):
  """Pretty-print a number of bytes."""
  if byts > 2**20.0:
    byts /= 2**20.0
    return '%.2fm' % byts
  if byts > 2**10.0:
    byts /= 2**10.0
    return '%.2fk' % byts
  return str(byts)


def _CalculateCompressedSize(file_path):
  CHUNK_SIZE = 256 * 1024
  compressor = zlib.compressobj()
  total_size = 0
  with open(file_path, 'rb') as f:
    for chunk in iter(lambda: f.read(CHUNK_SIZE), ''):
      total_size += len(compressor.compress(chunk))
  total_size += len(compressor.flush())
  return total_size


def _PrintDexAnalysis(apk_filename, chartjson=None):
  sizes = method_count.ExtractSizesFromZip(apk_filename)

  graph_title = os.path.basename(apk_filename) + '_Dex'
  dex_metrics = method_count.CONTRIBUTORS_TO_DEX_CACHE
  for key, label in dex_metrics.iteritems():
    ReportPerfResult(chartjson, graph_title, label, sizes[key], 'entries')

  graph_title = '%sCache' % graph_title
  ReportPerfResult(chartjson, graph_title, 'DexCache', sizes['dex_cache_size'],
                   'bytes')


def _PrintPatchSizeEstimate(new_apk, builder, bucket, chartjson=None):
  apk_name = os.path.basename(new_apk)
  title = apk_name + '_PatchSizeEstimate'
  # Reference APK paths have spaces replaced by underscores.
  builder = builder.replace(' ', '_')
  old_apk = apk_downloader.MaybeDownloadApk(
      builder, apk_downloader.CURRENT_MILESTONE, apk_name,
      apk_downloader.DEFAULT_DOWNLOAD_PATH, bucket)
  if old_apk:
    # Use a temp dir in case patch size functions fail to clean up temp files.
    with build_utils.TempDir() as tmp:
      tmp_name = os.path.join(tmp, 'patch.tmp')
      bsdiff = apk_patch_size_estimator.calculate_bsdiff(
          old_apk, new_apk, None, tmp_name)
      ReportPerfResult(chartjson, title, 'BSDiff (gzipped)', bsdiff, 'bytes')
      fbf = apk_patch_size_estimator.calculate_filebyfile(
          old_apk, new_apk, None, tmp_name)
      ReportPerfResult(chartjson, title, 'FileByFile (gzipped)', fbf, 'bytes')


@contextmanager
def Unzip(zip_file, filename=None):
  """Utility for temporary use of a single file in a zip archive."""
  with build_utils.TempDir() as unzipped_dir:
    unzipped_files = build_utils.ExtractAll(
        zip_file, unzipped_dir, True, pattern=filename)
    if len(unzipped_files) == 0:
      raise Exception(
          '%s not found in %s' % (filename, zip_file))
    yield unzipped_files[0]


def _VerifyLibBuildIdsMatch(tools_prefix, *so_files):
  if len(set(_ParseLibBuildId(f, tools_prefix) for f in so_files)) > 1:
    raise Exception('Found differing build ids in output directory and apk. '
                    'Your output directory is likely stale.')


def _ReadBuildVars(output_dir):
  with open(os.path.join(output_dir, 'build_vars.txt')) as f:
    return dict(l.replace('//', '').rstrip().split('=', 1) for l in f)


def main():
  argparser = argparse.ArgumentParser(description='Print APK size metrics.')
  argparser.add_argument('--min-pak-resource-size', type=int, default=20*1024,
                         help='Minimum byte size of displayed pak resources.')
  argparser.add_argument('--chromium-output-directory',
                         help='Location of the build artifacts.')
  argparser.add_argument('--chartjson', action='store_true',
                         help='Sets output mode to chartjson.')
  argparser.add_argument('--output-dir', default='.',
                         help='Directory to save chartjson to.')
  argparser.add_argument('--no-output-dir', action='store_true',
                         help='Skip all measurements that rely on having '
                         'output-dir')
  argparser.add_argument('--dump-static-initializers', action='store_true',
                         help='Run dump-static-initializers.py to get the list'
                         'of static initializers (slow).')
  argparser.add_argument('-d', '--device',
                         help='Dummy option for perf runner.')
  argparser.add_argument('--estimate-patch-size', action='store_true',
                         help='Include patch size estimates. Useful for perf '
                         'builders where a reference APK is available but adds '
                         '~3 mins to run time.')
  argparser.add_argument('--reference-apk-builder',
                         default=apk_downloader.DEFAULT_BUILDER,
                         help='Builder name to use for reference APK for patch '
                         'size estimates.')
  argparser.add_argument('--reference-apk-bucket',
                         default=apk_downloader.DEFAULT_BUCKET,
                         help='Storage bucket holding reference APKs.')
  argparser.add_argument('apk', help='APK file path.')
  args = argparser.parse_args()

  chartjson = _BASE_CHART.copy() if args.chartjson else None
  if args.chromium_output_directory:
    constants.SetOutputDirectory(args.chromium_output_directory)
  if not args.no_output_dir:
    constants.CheckOutputDirectory()
    devil_chromium.Initialize()
    build_vars = _ReadBuildVars(constants.GetOutDirectory())
    tools_prefix = os.path.join(constants.GetOutDirectory(),
                                build_vars['android_tool_prefix'])
  else:
    tools_prefix = ''

  PrintApkAnalysis(args.apk, tools_prefix, chartjson=chartjson)
  _PrintDexAnalysis(args.apk, chartjson=chartjson)
  if args.estimate_patch_size:
    _PrintPatchSizeEstimate(args.apk, args.reference_apk_builder,
                            args.reference_apk_bucket, chartjson=chartjson)
  if not args.no_output_dir:
    PrintPakAnalysis(args.apk, args.min_pak_resource_size)
    _PrintStaticInitializersCountFromApk(
        args.apk, tools_prefix, args.dump_static_initializers,
        chartjson=chartjson)
  if chartjson:
    results_path = os.path.join(args.output_dir, 'results-chart.json')
    logging.critical('Dumping json to %s', results_path)
    with open(results_path, 'w') as json_file:
      json.dump(chartjson, json_file)


if __name__ == '__main__':
  sys.exit(main())

#!/usr/bin/python
# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Prints the size of each given file and optionally computes the size of
   libchrome.so without the dependencies added for building with android NDK.
   Also breaks down the contents of the APK to determine the installed size
   and assign size contributions to different classes of file.
"""

import collections
import json
import logging
import operator
import optparse
import os
import re
import struct
import sys
import tempfile
import zipfile
import zlib

import devil_chromium
from devil.utils import cmd_helper
import method_count
from pylib import constants
from pylib.constants import host_paths

_GRIT_PATH = os.path.join(host_paths.DIR_SOURCE_ROOT, 'tools', 'grit')

# Prepend the grit module from the source tree so it takes precedence over other
# grit versions that might present in the search path.
with host_paths.SysPath(_GRIT_PATH, 1):
  from grit.format import data_pack # pylint: disable=import-error

with host_paths.SysPath(host_paths.BUILD_COMMON_PATH):
  import perf_tests_results_helper # pylint: disable=import-error


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

# Static initializers expected in official builds. Note that this list is built
# using 'nm' on libchrome.so which results from a GCC official build (i.e.
# Clang is not supported currently).

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


def CountStaticInitializers(so_path):
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
  stdout = cmd_helper.GetCmdOutput(['readelf', '-h', so_path])
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
  stdout = cmd_helper.GetCmdOutput(['readelf', '-SW', so_path])
  has_init_array, init_array_size = get_elf_section_size(stdout, 'init_array')
  if has_init_array:
    si_count = init_array_size / word_size
  si_count = max(si_count, 0)
  return si_count


def GetStaticInitializers(so_path):
  output = cmd_helper.GetCmdOutput([_DUMP_STATIC_INITIALIZERS_PATH, '-d',
                                    so_path])
  return output.splitlines()


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


def PrintResourceSizes(files, chartjson=None):
  """Prints the sizes of each given file.

     Args:
       files: List of files to print sizes for.
  """
  for f in files:
    ReportPerfResult(chartjson, 'ResourceSizes', os.path.basename(f) + ' size',
                     os.path.getsize(f), 'bytes')


class _FileGroup(object):
  """Represents a category that apk files can fall into."""

  def __init__(self, name):
    self.name = name
    self._zip_infos = []
    self._extracted = []

  def AddZipInfo(self, zip_info, extracted=False):
    self._zip_infos.append(zip_info)
    self._extracted.append(extracted)

  def GetNumEntries(self):
    return len(self._zip_infos)

  def FindByPattern(self, pattern):
    return next(i for i in self._zip_infos if re.match(pattern, i.filename))

  def FindLargest(self):
    return max(self._zip_infos, key=lambda i: i.file_size)

  def ComputeZippedSize(self):
    return sum(i.compress_size for i in self._zip_infos)

  def ComputeUncompressedSize(self):
    return sum(i.file_size for i in self._zip_infos)

  def ComputeExtractedSize(self):
    ret = 0
    for zi, extracted in zip(self._zip_infos, self._extracted):
      if extracted:
        ret += zi.file_size
    return ret

  def ComputeInstallSize(self):
    return self.ComputeExtractedSize() + self.ComputeZippedSize()


def PrintApkAnalysis(apk_filename, chartjson=None):
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
  icu_data = make_group('ICU (i18n library) data')
  v8_snapshots = make_group('V8 Snapshots')
  png_drawables = make_group('PNG drawables')
  res_directory = make_group('Non-compiled Android resources')
  arsc = make_group('Compiled Android resources')
  metadata = make_group('Package metadata')
  unknown = make_group('Unknown files')

  apk = zipfile.ZipFile(apk_filename, 'r')
  try:
    apk_contents = apk.infolist()
  finally:
    apk.close()

  total_apk_size = os.path.getsize(apk_filename)
  apk_basename = os.path.basename(apk_filename)

  for member in apk_contents:
    filename = member.filename
    if filename.endswith('/'):
      continue

    if filename.endswith('.so'):
      native_code.AddZipInfo(member, 'crazy' not in filename)
    elif filename.endswith('.dex'):
      java_code.AddZipInfo(member, True)
    elif re.search(r'^assets/.*(resources|percent)\.pak$', filename):
      native_resources_no_translations.AddZipInfo(member)
    elif re.search(r'\.lpak$|^assets/.*(?!resources|percent)\.pak$', filename):
      translations.AddZipInfo(member, 'en_' in filename or 'en-' in filename)
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

  # Main metric that we want to monitor for jumps.
  normalized_apk_size = total_apk_size
  # Always look at uncompressed .dex & .so.
  normalized_apk_size -= java_code.ComputeZippedSize()
  normalized_apk_size += java_code.ComputeUncompressedSize()
  normalized_apk_size -= native_code.ComputeZippedSize()
  normalized_apk_size += native_code.ComputeUncompressedSize()
  # Avoid noise caused when strings change and translations haven't yet been
  # updated.
  english_pak = translations.FindByPattern(r'.*/en[-_][Uu][Ss]\.l?pak')
  if english_pak:
    normalized_apk_size -= translations.ComputeZippedSize()
    # 1.17 found by looking at Chrome.apk and seeing how much smaller en-US.pak
    # is relative to the average locale .pak.
    normalized_apk_size += int(
        english_pak.compress_size * translations.GetNumEntries() * 1.17)

  ReportPerfResult(chartjson, apk_basename + '_Specifics',
                   'normalized apk size', normalized_apk_size, 'bytes')

  ReportPerfResult(chartjson, apk_basename + '_Specifics',
                   'file count', len(apk_contents), 'zip entries')


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

  resource_id_name_map = _GetResourceIdNameMap()

  # Output the table of details about all resources across pak files.
  print
  print '%56s %5s %17s' % ('RESOURCE', 'COUNT', 'UNCOMPRESSED SIZE')
  for i in sorted(resource_size_map, key=resource_size_map.get,
                  reverse=True):
    if resource_size_map[i] >= min_pak_resource_size:
      print '%56s %5s %9s %6.2f%%' % (
          resource_id_name_map.get(i, i),
          resource_count_map[i],
          _FormatBytes(resource_size_map[i]),
          100.0 * resource_size_map[i] / total_resource_size)


def _GetResourceIdNameMap():
  """Returns a map of {resource_id: resource_name}."""
  out_dir = constants.GetOutDirectory()
  assert os.path.isdir(out_dir), 'Failed to locate out dir at %s' % out_dir
  print 'Looking at resources in: %s' % out_dir

  grit_headers = []
  for root, _, files in os.walk(out_dir):
    if root.endswith('grit'):
      grit_headers += [os.path.join(root, f) for f in files if f.endswith('.h')]
  assert grit_headers, 'Failed to find grit headers in %s' % out_dir

  id_name_map = {}
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
  return id_name_map


def _PrintStaticInitializersCountFromApk(apk_filename, chartjson=None):
  print 'Finding static initializers (can take a minute)'
  with zipfile.ZipFile(apk_filename) as z:
    infolist = z.infolist()
  out_dir = constants.GetOutDirectory()
  si_count = 0
  for zip_info in infolist:
    # Check file size to account for placeholder libraries.
    if zip_info.filename.endswith('.so') and zip_info.file_size > 0:
      lib_name = os.path.basename(zip_info.filename).replace('crazy.', '')
      unstripped_path = os.path.join(out_dir, 'lib.unstripped', lib_name)
      if os.path.exists(unstripped_path):
        si_count += _PrintStaticInitializersCount(unstripped_path)
      else:
        raise Exception('Unstripped .so not found. Looked here: %s',
                        unstripped_path)
  ReportPerfResult(chartjson, 'StaticInitializersCount', 'count', si_count,
                   'count')


def _PrintStaticInitializersCount(so_with_symbols_path):
  """Counts the number of static initializers in the given shared library.
     Additionally, files for which static initializers were found are printed
     on the standard output.

     Args:
       so_with_symbols_path: Path to the unstripped libchrome.so file.

     Returns:
       The number of static initializers found.
  """
  # GetStaticInitializers uses get-static-initializers.py to get a list of all
  # static initializers. This does not work on all archs (particularly arm).
  # TODO(rnephew): Get rid of warning when crbug.com/585588 is fixed.
  si_count = CountStaticInitializers(so_with_symbols_path)
  static_initializers = GetStaticInitializers(so_with_symbols_path)
  static_initializers_count = len(static_initializers) - 1  # Minus summary.
  if si_count != static_initializers_count:
    print ('There are %d files with static initializers, but '
           'dump-static-initializers found %d:' %
           (si_count, static_initializers_count))
  else:
    print '%s - Found %d files with static initializers:' % (
        os.path.basename(so_with_symbols_path), si_count)
  print '\n'.join(static_initializers)

  return si_count

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


def main(argv):
  usage = """Usage: %prog [options] file1 file2 ...

Pass any number of files to graph their sizes. Any files with the extension
'.apk' will be broken down into their components on a separate graph."""
  option_parser = optparse.OptionParser(usage=usage)
  option_parser.add_option('--so-path',
                           help='Obsolete. Pass .so as positional arg instead.')
  option_parser.add_option('--so-with-symbols-path',
                           help='Mostly obsolete. Use .so within .apk instead.')
  option_parser.add_option('--min-pak-resource-size', type='int',
                           default=20*1024,
                           help='Minimum byte size of displayed pak resources.')
  option_parser.add_option('--build_type', dest='build_type', default='Debug',
                           help='Obsoleted by --chromium-output-directory.')
  option_parser.add_option('--chromium-output-directory',
                           help='Location of the build artifacts. '
                                'Takes precidence over --build_type.')
  option_parser.add_option('--chartjson', action='store_true',
                           help='Sets output mode to chartjson.')
  option_parser.add_option('--output-dir', default='.',
                           help='Directory to save chartjson to.')
  option_parser.add_option('--no-output-dir', action='store_true',
                           help='Skip all measurements that rely on having '
                                'output-dir')
  option_parser.add_option('-d', '--device',
                           help='Dummy option for perf runner.')
  options, args = option_parser.parse_args(argv)
  files = args[1:]
  chartjson = _BASE_CHART.copy() if options.chartjson else None

  constants.SetBuildType(options.build_type)
  if options.chromium_output_directory:
    constants.SetOutputDirectory(options.chromium_output_directory)
  if not options.no_output_dir:
    constants.CheckOutputDirectory()
    devil_chromium.Initialize()

  # For backward compatibilty with buildbot scripts, treat --so-path as just
  # another file to print the size of. We don't need it for anything special any
  # more.
  if options.so_path:
    files.append(options.so_path)

  if not files:
    option_parser.error('Must specify a file')

  if options.so_with_symbols_path:
    si_count = _PrintStaticInitializersCount(options.so_with_symbols_path)
    ReportPerfResult(chartjson, 'StaticInitializersCount', 'count', si_count,
                     'count')

  PrintResourceSizes(files, chartjson=chartjson)

  for f in files:
    if f.endswith('.apk'):
      PrintApkAnalysis(f, chartjson=chartjson)
      _PrintDexAnalysis(f, chartjson=chartjson)
      if not options.no_output_dir:
        PrintPakAnalysis(f, options.min_pak_resource_size)
        if not options.so_with_symbols_path:
          _PrintStaticInitializersCountFromApk(f, chartjson=chartjson)

  if chartjson:
    results_path = os.path.join(options.output_dir, 'results-chart.json')
    logging.critical('Dumping json to %s', results_path)
    with open(results_path, 'w') as json_file:
      json.dump(chartjson, json_file)


if __name__ == '__main__':
  sys.exit(main(sys.argv))

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
import operator
import optparse
import os
import re
import sys
import tempfile
import zipfile
import zlib

import devil_chromium
from devil.utils import cmd_helper
from pylib.constants import host_paths

_GRIT_PATH = os.path.join(host_paths.DIR_SOURCE_ROOT, 'tools', 'grit')

with host_paths.SysPath(_GRIT_PATH):
  from grit.format import data_pack # pylint: disable=import-error

with host_paths.SysPath(host_paths.BUILD_COMMON_PATH):
  import perf_tests_results_helper # pylint: disable=import-error


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
_RC_HEADER_RE = re.compile(r'^#define (?P<name>\w+) (?P<id>\d+)$')


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


def PrintApkAnalysis(apk_filename, chartjson=None):
  """Analyse APK to determine size contributions of different file classes."""
  # Define a named tuple type for file grouping.
  # name: Human readable name for this file group
  # regex: Regular expression to match filename
  # extracted: Function that takes a file name and returns whether the file is
  #            extracted from the apk at install/runtime.
  FileGroup = collections.namedtuple('FileGroup',
                                     ['name', 'regex', 'extracted'])

  # File groups are checked in sequence, so more specific regexes should be
  # earlier in the list.
  YES = lambda _: True
  NO = lambda _: False
  FILE_GROUPS = (
      FileGroup('Native code', r'\.so$', lambda f: 'crazy' not in f),
      FileGroup('Java code', r'\.dex$', YES),
      FileGroup('Native resources (no l10n)', r'\.pak$', NO),
      # For locale paks, assume only english paks are extracted.
      FileGroup('Native resources (l10n)', r'\.lpak$', lambda f: 'en_' in f),
      FileGroup('ICU (i18n library) data', r'assets/icudtl\.dat$', NO),
      FileGroup('V8 Snapshots', r'\.bin$', NO),
      FileGroup('PNG drawables', r'\.png$', NO),
      FileGroup('Non-compiled Android resources', r'^res/', NO),
      FileGroup('Compiled Android resources', r'\.arsc$', NO),
      FileGroup('Package metadata', r'^(META-INF/|AndroidManifest\.xml$)', NO),
      FileGroup('Unknown files', r'.', NO),
      )

  apk = zipfile.ZipFile(apk_filename, 'r')
  try:
    apk_contents = apk.infolist()
  finally:
    apk.close()

  total_apk_size = os.path.getsize(apk_filename)
  apk_basename = os.path.basename(apk_filename)

  found_files = {}
  for group in FILE_GROUPS:
    found_files[group] = []

  for member in apk_contents:
    for group in FILE_GROUPS:
      if re.search(group.regex, member.filename):
        found_files[group].append(member)
        break
    else:
      raise KeyError('No group found for file "%s"' % member.filename)

  total_install_size = total_apk_size

  for group in FILE_GROUPS:
    apk_size = sum(member.compress_size for member in found_files[group])
    install_size = apk_size
    install_bytes = sum(f.file_size for f in found_files[group]
                        if group.extracted(f.filename))
    install_size += install_bytes
    total_install_size += install_bytes

    ReportPerfResult(chartjson, apk_basename + '_Breakdown',
                     group.name + ' size', apk_size, 'bytes')
    ReportPerfResult(chartjson, apk_basename + '_InstallBreakdown',
                     group.name + ' size', install_size, 'bytes')

  transfer_size = _CalculateCompressedSize(apk_filename)
  ReportPerfResult(chartjson, apk_basename + '_InstallSize',
                   'Estimated installed size', total_install_size, 'bytes')
  ReportPerfResult(chartjson, apk_basename + '_InstallSize', 'APK size',
                   total_apk_size, 'bytes')
  ReportPerfResult(chartjson, apk_basename + '_TransferSize',
                   'Transfer size (deflate)', transfer_size, 'bytes')


def IsPakFileName(file_name):
  """Returns whether the given file name ends with .pak or .lpak."""
  return file_name.endswith('.pak') or file_name.endswith('.lpak')


def PrintPakAnalysis(apk_filename, min_pak_resource_size, build_type):
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

  resource_id_name_map = _GetResourceIdNameMap(build_type)

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


def _GetResourceIdNameMap(build_type):
  """Returns a map of {resource_id: resource_name}."""
  out_dir = os.path.join(host_paths.DIR_SOURCE_ROOT, 'out', build_type)
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


def PrintStaticInitializersCount(so_with_symbols_path, chartjson=None):
  """Emits the performance result for static initializers found in the provided
     shared library. Additionally, files for which static initializers were
     found are printed on the standard output.

     Args:
       so_with_symbols_path: Path to the unstripped libchrome.so file.
  """
  # GetStaticInitializers uses get-static-initializers.py to get a list of all
  # static initializers. This does not work on all archs (particularly arm).
  # TODO(rnephew): Get rid of warning when crbug.com/585588 is fixed.
  si_count = CountStaticInitializers(so_with_symbols_path)
  static_initializers = GetStaticInitializers(so_with_symbols_path)
  if si_count != len(static_initializers):
    print ('There are %d files with static initializers, but '
           'dump-static-initializers found %d:' %
           (si_count, len(static_initializers)))
  else:
    print 'Found %d files with static initializers:' % si_count
  print '\n'.join(static_initializers)

  ReportPerfResult(chartjson, 'StaticInitializersCount', 'count',
                   si_count, 'count')

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


def main(argv):
  usage = """Usage: %prog [options] file1 file2 ...

Pass any number of files to graph their sizes. Any files with the extension
'.apk' will be broken down into their components on a separate graph."""
  option_parser = optparse.OptionParser(usage=usage)
  option_parser.add_option('--so-path', help='Path to libchrome.so.')
  option_parser.add_option('--so-with-symbols-path',
                           help='Path to libchrome.so with symbols.')
  option_parser.add_option('--min-pak-resource-size', type='int',
                           default=20*1024,
                           help='Minimum byte size of displayed pak resources.')
  option_parser.add_option('--build_type', dest='build_type', default='Debug',
                           help='Sets the build type, default is Debug.')
  option_parser.add_option('--chartjson', action="store_true",
                           help='Sets output mode to chartjson.')
  option_parser.add_option('--output-dir', default='.',
                           help='Directory to save chartjson to.')
  option_parser.add_option('-d', '--device',
                           help='Dummy option for perf runner.')
  options, args = option_parser.parse_args(argv)
  files = args[1:]
  chartjson = _BASE_CHART.copy() if options.chartjson else None

  # For backward compatibilty with buildbot scripts, treat --so-path as just
  # another file to print the size of. We don't need it for anything special any
  # more.
  if options.so_path:
    files.append(options.so_path)

  if not files:
    option_parser.error('Must specify a file')

  devil_chromium.Initialize()

  if options.so_with_symbols_path:
    PrintStaticInitializersCount(
        options.so_with_symbols_path, chartjson=chartjson)

  PrintResourceSizes(files, chartjson=chartjson)

  for f in files:
    if f.endswith('.apk'):
      PrintApkAnalysis(f, chartjson=chartjson)
      PrintPakAnalysis(f, options.min_pak_resource_size, options.build_type)

  if chartjson:
    results_path = os.path.join(options.output_dir, 'results-chart.json')
    with open(results_path, 'w') as json_file:
      json.dump(chartjson, json_file)


if __name__ == '__main__':
  sys.exit(main(sys.argv))

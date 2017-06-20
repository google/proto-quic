#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tool for finding the cause of binary size bloat.

See //tools/binary_size/README.md for example usage.

Note: this tool will perform gclient sync/git checkout on your local repo if
you don't use the --cloud option.
"""

import atexit
import argparse
import collections
from contextlib import contextmanager
import distutils.spawn
import json
import logging
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

_COMMIT_COUNT_WARN_THRESHOLD = 15
_ALLOWED_CONSECUTIVE_FAILURES = 2
_DIFF_DETAILS_LINES_THRESHOLD = 100
_SRC_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
_DEFAULT_ARCHIVE_DIR = os.path.join(_SRC_ROOT, 'out', 'binary-size-results')
_DEFAULT_OUT_DIR = os.path.join(_SRC_ROOT, 'out', 'binary-size-build')
_DEFAULT_ANDROID_TARGET = 'monochrome_public_apk'
_BINARY_SIZE_DIR = os.path.join(_SRC_ROOT, 'tools', 'binary_size')


_DiffResult = collections.namedtuple('DiffResult', ['name', 'value', 'units'])


class BaseDiff(object):
  """Base class capturing binary size diffs."""
  def __init__(self, name):
    self.name = name
    self.banner = '\n' + '*' * 30 + name + '*' * 30

  def AppendResults(self, logfile):
    """Print and write diff results to an open |logfile|."""
    _PrintAndWriteToFile(logfile, self.banner)
    _PrintAndWriteToFile(logfile, 'Summary:')
    _PrintAndWriteToFile(logfile, self.Summary())
    _PrintAndWriteToFile(logfile, '\nDetails:')
    _PrintAndWriteToFile(logfile, self.DetailedResults())

  @property
  def summary_stat(self):
    return None

  def Summary(self):
    """A short description that summarizes the source of binary size bloat."""
    raise NotImplementedError()

  def DetailedResults(self):
    """An iterable description of the cause of binary size bloat."""
    raise NotImplementedError()

  def ProduceDiff(self, before_dir, after_dir):
    """Prepare a binary size diff with ready to print results."""
    raise NotImplementedError()

  def RunDiff(self, logfile, before_dir, after_dir):
    logging.info('Creating: %s', self.name)
    self.ProduceDiff(before_dir, after_dir)
    self.AppendResults(logfile)


class NativeDiff(BaseDiff):
  _RE_SUMMARY = re.compile(r'Section Sizes .*?\n\n.*?(?=\n\n)', flags=re.DOTALL)
  _RE_SUMMARY_STAT = re.compile(
      r'Section Sizes \(Total=(?P<value>\d+) (?P<units>\w+)\)')
  _SUMMARY_STAT_NAME = 'Native Library Delta'

  def __init__(self, size_name, supersize_path):
    self._size_name = size_name
    self._supersize_path = supersize_path
    self._diff = []
    super(NativeDiff, self).__init__('Native Diff')

  @property
  def summary_stat(self):
    m = NativeDiff._RE_SUMMARY_STAT.search(self._diff)
    if m:
      return _DiffResult(
          NativeDiff._SUMMARY_STAT_NAME, m.group('value'), m.group('units'))
    return None

  def DetailedResults(self):
    return self._diff.splitlines()

  def Summary(self):
    return NativeDiff._RE_SUMMARY.search(self._diff).group()

  def ProduceDiff(self, before_dir, after_dir):
    before_size = os.path.join(before_dir, self._size_name)
    after_size = os.path.join(after_dir, self._size_name)
    cmd = [self._supersize_path, 'diff', before_size, after_size]
    self._diff = _RunCmd(cmd)[0].replace('{', '{{').replace('}', '}}')


class ResourceSizesDiff(BaseDiff):
  _RESOURCE_SIZES_PATH = os.path.join(
      _SRC_ROOT, 'build', 'android', 'resource_sizes.py')

  def __init__(self, apk_name, slow_options=False):
    self._apk_name = apk_name
    self._slow_options = slow_options
    self._diff = None  # Set by |ProduceDiff()|
    super(ResourceSizesDiff, self).__init__('Resource Sizes Diff')

  @property
  def summary_stat(self):
    for s in self._diff:
      if 'normalized' in s.name:
        return s
    return None

  def DetailedResults(self):
    return ['{:>+10,} {} {}'.format(value, units, name)
            for name, value, units in self._diff]

  def Summary(self):
    return 'Normalized APK size: {:+,} {}'.format(
        self.summary_stat.value, self.summary_stat.units)

  def ProduceDiff(self, before_dir, after_dir):
    before = self._RunResourceSizes(before_dir)
    after = self._RunResourceSizes(after_dir)
    diff = []
    for section, section_dict in after.iteritems():
      for subsection, v in section_dict.iteritems():
        # Ignore entries when resource_sizes.py chartjson format has changed.
        if (section not in before or
            subsection not in before[section] or
            v['units'] != before[section][subsection]['units']):
          logging.warning(
              'Found differing dict structures for resource_sizes.py, '
              'skipping %s %s', section, subsection)
        else:
          diff.append(
              _DiffResult(
                  '%s %s' % (section, subsection),
                  v['value'] - before[section][subsection]['value'],
                  v['units']))
    self._diff = sorted(diff, key=lambda x: abs(x.value), reverse=True)

  def _RunResourceSizes(self, archive_dir):
    apk_path = os.path.join(archive_dir, self._apk_name)
    chartjson_file = os.path.join(archive_dir, 'results-chart.json')
    cmd = [self._RESOURCE_SIZES_PATH, apk_path,'--output-dir', archive_dir,
           '--no-output-dir', '--chartjson']
    if self._slow_options:
      cmd += ['--estimate-patch-size', '--dump-static-initializers']
    _RunCmd(cmd)
    with open(chartjson_file) as f:
      chartjson = json.load(f)
    return chartjson['charts']


class _BuildHelper(object):
  """Helper class for generating and building targets."""
  def __init__(self, args):
    self.cloud = args.cloud
    self.enable_chrome_android_internal = args.enable_chrome_android_internal
    self.extra_gn_args_str = ''
    self.max_jobs = args.max_jobs
    self.max_load_average = args.max_load_average
    self.output_directory = args.output_directory
    self.target = args.target
    self.target_os = args.target_os
    self.use_goma = args.use_goma
    self._SetDefaults()

  @property
  def abs_apk_path(self):
    return os.path.join(self.output_directory, self.apk_path)

  @property
  def apk_name(self):
    # Only works on apk targets that follow: my_great_apk naming convention.
    apk_name = ''.join(s.title() for s in self.target.split('_')[:-1]) + '.apk'
    return apk_name.replace('Webview', 'WebView')

  @property
  def apk_path(self):
    return os.path.join('apks', self.apk_name)

  @property
  def main_lib_path(self):
    # TODO(estevenson): Get this from GN instead of hardcoding.
    if self.IsLinux():
      return 'chrome'
    elif 'monochrome' in self.target:
      return 'lib.unstripped/libmonochrome.so'
    else:
      return 'lib.unstripped/libchrome.so'

  @property
  def abs_main_lib_path(self):
    return os.path.join(self.output_directory, self.main_lib_path)

  @property
  def builder_url(self):
    url = 'https://build.chromium.org/p/chromium.perf/builders/%s%%20Builder'
    return url % self.target_os.title()

  @property
  def download_bucket(self):
    return 'gs://chrome-perf/%s Builder/' % self.target_os.title()

  @property
  def map_file_path(self):
    return self.main_lib_path + '.map.gz'

  @property
  def size_name(self):
    if self.IsLinux():
      return os.path.basename(self.main_lib_path) + '.size'
    return self.apk_name + '.size'

  def _SetDefaults(self):
    has_goma_dir = os.path.exists(os.path.join(os.path.expanduser('~'), 'goma'))
    self.use_goma = self.use_goma or has_goma_dir
    self.max_load_average = (self.max_load_average or
                             str(multiprocessing.cpu_count()))
    if not self.max_jobs:
      self.max_jobs = '10000' if self.use_goma else '500'

    if os.path.exists(os.path.join(os.path.dirname(_SRC_ROOT), 'src-internal')):
      self.extra_gn_args_str = ' is_chrome_branded=true'
    else:
      self.extra_gn_args_str = (' exclude_unwind_tables=true '
          'ffmpeg_branding="Chrome" proprietary_codecs=true')
    if self.IsLinux():
      self.extra_gn_args_str += (
          ' allow_posix_link_time_opt=false generate_linker_map=true')
    self.target = self.target if self.IsAndroid() else 'chrome'

  def _GenGnCmd(self):
    gn_args = 'is_official_build=true symbol_level=1'
    gn_args += ' use_goma=%s' % str(self.use_goma).lower()
    gn_args += ' target_os="%s"' % self.target_os
    if self.IsAndroid():
      gn_args += (' enable_chrome_android_internal=%s' %
                  str(self.enable_chrome_android_internal).lower())
    gn_args += self.extra_gn_args_str
    return ['gn', 'gen', self.output_directory, '--args=%s' % gn_args]

  def _GenNinjaCmd(self):
    cmd = ['ninja', '-C', self.output_directory]
    cmd += ['-j', self.max_jobs] if self.max_jobs else []
    cmd += ['-l', self.max_load_average] if self.max_load_average else []
    cmd += [self.target]
    return cmd

  def Run(self):
    """Run GN gen/ninja build and return the process returncode."""
    logging.info('Building %s within %s (this might take a while).',
                 self.target, os.path.relpath(self.output_directory))
    retcode = _RunCmd(
        self._GenGnCmd(), verbose=True, exit_on_failure=False)[1]
    if retcode:
      return retcode
    return _RunCmd(
        self._GenNinjaCmd(), verbose=True, exit_on_failure=False)[1]

  def DownloadUrl(self, rev):
    return self.download_bucket + 'full-build-linux_%s.zip' % rev

  def IsAndroid(self):
    return self.target_os == 'android'

  def IsLinux(self):
    return self.target_os == 'linux'

  def IsCloud(self):
    return self.cloud


class _BuildArchive(object):
  """Class for managing a directory with build results and build metadata."""
  def __init__(self, rev, base_archive_dir, build, subrepo):
    self.build = build
    self.dir = os.path.join(base_archive_dir, rev)
    metadata_path = os.path.join(self.dir, 'metadata.txt')
    self.rev = rev
    self.metadata = _Metadata([self], build, metadata_path, subrepo)

  def ArchiveBuildResults(self, supersize_path):
    """Save build artifacts necessary for diffing."""
    logging.info('Saving build results to: %s', self.dir)
    _EnsureDirsExist(self.dir)
    self._ArchiveFile(self.build.abs_main_lib_path)
    if self.build.IsAndroid():
      self._ArchiveFile(self.build.abs_apk_path)
    self._ArchiveSizeFile(supersize_path)
    self.metadata.Write()

  def Exists(self):
    return self.metadata.Exists()

  def _ArchiveFile(self, filename):
    if not os.path.exists(filename):
      _Die('missing expected file: %s', filename)
    shutil.copy(filename, self.dir)

  def _ArchiveSizeFile(self, supersize_path):
    existing_size_file = self.build.abs_apk_path + '.size'
    if os.path.exists(existing_size_file):
      logging.info('Found existing .size file')
      os.rename(
          existing_size_file, os.path.join(self.dir, self.build.size_name))
    else:
      size_path = os.path.join(self.dir, self.build.size_name)
      supersize_cmd = [supersize_path, 'archive', size_path, '--elf-file',
                       self.build.abs_main_lib_path]
      if self.build.IsCloud():
        supersize_cmd += ['--no-source-paths']
      else:
        supersize_cmd += ['--output-directory', self.build.output_directory]
      if self.build.IsAndroid():
        supersize_cmd += ['--apk-file', self.build.abs_apk_path]
      logging.info('Creating .size file')
      _RunCmd(supersize_cmd)


class _DiffArchiveManager(object):
  """Class for maintaining BuildArchives and their related diff artifacts."""
  def __init__(self, revs, archive_dir, diffs, build, subrepo):
    self.archive_dir = archive_dir
    self.build = build
    self.build_archives = [_BuildArchive(rev, archive_dir, build, subrepo)
                           for rev in revs]
    self.diffs = diffs
    self.subrepo = subrepo
    self._summary_stats = []

  def IterArchives(self):
    return iter(self.build_archives)

  def MaybeDiff(self, before_id, after_id):
    """Perform diffs given two build archives."""
    before = self.build_archives[before_id]
    after = self.build_archives[after_id]
    diff_path = self._DiffFilePath(before, after)
    if not self._CanDiff(before, after):
      logging.info(
          'Skipping diff for %s due to missing build archives.', diff_path)
      return

    metadata_path = self._DiffMetadataPath(before, after)
    metadata = _Metadata(
        [before, after], self.build, metadata_path, self.subrepo)
    if metadata.Exists():
      logging.info(
          'Skipping diff for %s and %s. Matching diff already exists: %s',
          before.rev, after.rev, diff_path)
    else:
      if os.path.exists(diff_path):
        os.remove(diff_path)
      with open(diff_path, 'a') as diff_file:
        for d in self.diffs:
          d.RunDiff(diff_file, before.dir, after.dir)
        logging.info('See detailed diff results here: %s',
                     os.path.relpath(diff_path))
        if len(self.build_archives) == 2:
          supersize_path = os.path.join(_BINARY_SIZE_DIR, 'supersize')
          size_paths = [os.path.join(a.dir, a.build.size_name)
                        for a in self.build_archives]
          logging.info('Enter supersize console via: %s, console %s %s',
                       os.path.relpath(supersize_path),
                       os.path.relpath(size_paths[0]),
                       os.path.relpath(size_paths[1]))
      metadata.Write()
      self._AddDiffSummaryStat(before, after)

  def Summarize(self):
    if self._summary_stats:
      path = os.path.join(self.archive_dir, 'last_diff_summary.txt')
      with open(path, 'w') as f:
        stats = sorted(
            self._summary_stats, key=lambda x: x[0].value, reverse=True)
        _PrintAndWriteToFile(f, '\nDiff Summary')
        for s, before, after in stats:
          _PrintAndWriteToFile(f, '{:>+10} {} {} for range: {}..{}',
                               s.value, s.units, s.name, before, after)

  def _AddDiffSummaryStat(self, before, after):
    stat = None
    if self.build.IsAndroid():
      summary_diff_type = ResourceSizesDiff
    else:
      summary_diff_type = NativeDiff
    for d in self.diffs:
      if isinstance(d, summary_diff_type):
        stat = d.summary_stat
    if stat:
      self._summary_stats.append((stat, before.rev, after.rev))

  def _CanDiff(self, before, after):
    return before.Exists() and after.Exists()

  def _DiffFilePath(self, before, after):
    return os.path.join(self._DiffDir(before, after), 'diff_results.txt')

  def _DiffMetadataPath(self, before, after):
    return os.path.join(self._DiffDir(before, after), 'metadata.txt')

  def _DiffDir(self, before, after):
    archive_range = '%s..%s' % (before.rev, after.rev)
    diff_path = os.path.join(self.archive_dir, 'diffs', archive_range)
    _EnsureDirsExist(diff_path)
    return diff_path


class _Metadata(object):

  def __init__(self, archives, build, path, subrepo):
    self.is_cloud = build.IsCloud()
    self.data = {
      'revs': [a.rev for a in archives],
      'archive_dirs': [a.dir for a in archives],
      'target': build.target,
      'target_os': build.target_os,
      'is_cloud': build.IsCloud(),
      'subrepo': subrepo,
      'path': path,
      'gn_args': {
        'extra_gn_args_str': build.extra_gn_args_str,
        'enable_chrome_android_internal': build.enable_chrome_android_internal,
      }
    }

  def Exists(self):
    old_metadata = {}
    path = self.data['path']
    if os.path.exists(path):
      with open(path, 'r') as f:
        old_metadata = json.load(f)
        # For local builds, all keys need to be the same. Differing GN args will
        # make diffs noisy and inaccurate. GN args do not matter for --cloud
        # since we download prebuilt build artifacts.
        keys = self.data.keys()
        if self.is_cloud:
          keys.remove('gn_args')
        return all(v == old_metadata[k]
                   for k, v in self.data.iteritems() if k in keys)

  def Write(self):
    with open(self.data['path'], 'w') as f:
      json.dump(self.data, f)


def _EnsureDirsExist(path):
  if not os.path.exists(path):
    os.makedirs(path)


def _RunCmd(cmd, verbose=False, exit_on_failure=True):
  """Convenience function for running commands.

  Args:
    cmd: the command to run.
    verbose: if this is True, then the stdout and stderr of the process will be
        printed. If it's false, the stdout will be returned.
    exit_on_failure: die if an error occurs when this is True.

  Returns:
    Tuple of (process stdout, process returncode).
  """
  assert not (verbose and exit_on_failure)
  cmd_str = ' '.join(c for c in cmd)
  logging.debug('Running: %s', cmd_str)
  proc_stdout = proc_stderr = subprocess.PIPE
  if verbose and logging.getLogger().getEffectiveLevel() < logging.INFO:
    proc_stdout, proc_stderr = sys.stdout, subprocess.STDOUT

  proc = subprocess.Popen(cmd, stdout=proc_stdout, stderr=proc_stderr)
  stdout, stderr = proc.communicate()

  if proc.returncode and exit_on_failure:
    _Die('command failed: %s\nstderr:\n%s', cmd_str, stderr)

  stdout = stdout.strip() if stdout else ''
  return stdout, proc.returncode


def _GitCmd(args, subrepo):
  return _RunCmd(['git', '-C', subrepo] + args)[0]


def _GclientSyncCmd(rev, subrepo):
  cwd = os.getcwd()
  os.chdir(subrepo)
  _, retcode = _RunCmd(['gclient', 'sync', '-r', 'src@' + rev],
                       verbose=True, exit_on_failure=False)
  os.chdir(cwd)
  return retcode


def _SyncAndBuild(archive, build, subrepo):
  """Sync, build and return non 0 if any commands failed."""
  # Simply do a checkout if subrepo is used.
  retcode = 0
  if _CurrentGitHash(subrepo) == archive.rev:
    if subrepo != _SRC_ROOT:
      logging.info('Skipping git checkout since already at desired rev')
    else:
      logging.info('Skipping gclient sync since already at desired rev')
  elif subrepo != _SRC_ROOT:
    _GitCmd(['checkout',  archive.rev], subrepo)
  else:
    # Move to a detached state since gclient sync doesn't work with local
    # commits on a branch.
    _GitCmd(['checkout', '--detach'], subrepo)
    logging.info('Syncing to %s', archive.rev)
    retcode = _GclientSyncCmd(archive.rev, subrepo)
  return retcode or build.Run()


def _GenerateRevList(rev, reference_rev, all_in_range, subrepo):
  """Normalize and optionally generate a list of commits in the given range.

  Returns:
    A list of revisions ordered from oldest to newest.
  """
  rev_seq = '%s^..%s' % (reference_rev, rev)
  stdout = _GitCmd(['rev-list', rev_seq], subrepo)
  all_revs = stdout.splitlines()[::-1]
  if all_in_range:
    revs = all_revs
  else:
    revs = [all_revs[0], all_revs[-1]]
  if len(revs) >= _COMMIT_COUNT_WARN_THRESHOLD:
    _VerifyUserAccepts(
        'You\'ve provided a commit range that contains %d commits.' % len(revs))
  return revs


def _ValidateRevs(rev, reference_rev, subrepo):
  def git_fatal(args, message):
    devnull = open(os.devnull, 'wb')
    retcode = subprocess.call(
        ['git', '-C', subrepo] + args, stdout=devnull, stderr=subprocess.STDOUT)
    if retcode:
      _Die(message)

  if rev == reference_rev:
    _Die('rev and reference-rev cannot be equal')
  no_obj_message = ('%s either doesn\'t exist or your local repo is out of '
                    'date, try "git fetch origin master"')
  git_fatal(['cat-file', '-e', rev], no_obj_message % rev)
  git_fatal(['cat-file', '-e', reference_rev], no_obj_message % reference_rev)
  git_fatal(['merge-base', '--is-ancestor', reference_rev, rev],
            'reference-rev is newer than rev')
  return rev, reference_rev


def _VerifyUserAccepts(message):
  print message + ' Do you want to proceed? [y/n]'
  if raw_input('> ').lower() != 'y':
    sys.exit()


def _EnsureDirectoryClean(subrepo):
  logging.info('Checking source directory')
  stdout = _GitCmd(['status', '--porcelain'], subrepo)
  # Ignore untracked files.
  if stdout and stdout[:2] != '??':
    logging.error('Failure: please ensure working directory is clean.')
    sys.exit()


def _Die(s, *args):
  logging.error('Failure: ' + s, *args)
  sys.exit(1)


def _DownloadBuildArtifacts(archive, build, supersize_path, depot_tools_path):
  """Download artifacts from arm32 chromium perf builder."""
  if depot_tools_path:
    gsutil_path = os.path.join(depot_tools_path, 'gsutil.py')
  else:
    gsutil_path = distutils.spawn.find_executable('gsutil.py')

  if not gsutil_path:
    _Die('gsutil.py not found, please provide path to depot_tools via '
         '--depot-tools-path or add it to your PATH')

  download_dir = tempfile.mkdtemp(dir=_SRC_ROOT)
  try:
    _DownloadAndArchive(
        gsutil_path, archive, download_dir, build, supersize_path)
  finally:
    shutil.rmtree(download_dir)


def _DownloadAndArchive(gsutil_path, archive, dl_dir, build, supersize_path):
  proc = subprocess.Popen([gsutil_path, 'version'], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
  output, _ = proc.communicate()
  if proc.returncode:
    _Die('gsutil error. Please file a bug in Tools>BinarySize. Output:\n%s',
         output)

  dl_dst = os.path.join(dl_dir, archive.rev)
  logging.info('Downloading build artifacts for %s', archive.rev)
  # gsutil writes stdout and stderr to stderr, so pipe stdout and stderr to
  # sys.stdout.
  retcode = subprocess.call(
      [gsutil_path, 'cp', build.DownloadUrl(archive.rev), dl_dst],
      stdout=sys.stdout, stderr=subprocess.STDOUT)
  if retcode:
      _Die('unexpected error while downloading %s. It may no longer exist on '
           'the server or it may not have been uploaded yet (check %s). '
           'Otherwise, you may not have the correct access permissions.',
           build.DownloadUrl(archive.rev), build.builder_url)

  # Files needed for supersize and resource_sizes. Paths relative to out dir.
  to_extract = [build.main_lib_path, build.map_file_path, 'args.gn']
  if build.IsAndroid():
    to_extract += ['build_vars.txt', build.apk_path, build.apk_path + '.size']
  extract_dir = dl_dst + '_' + 'unzipped'
  logging.info('Extracting build artifacts')
  with zipfile.ZipFile(dl_dst, 'r') as z:
    dl_out = _ExtractFiles(to_extract, extract_dir, z)
    build.output_directory, output_directory = dl_out, build.output_directory
    archive.ArchiveBuildResults(supersize_path)
    build.output_directory = output_directory


def _ExtractFiles(to_extract, dst, z):
  """Extract a list of files. Returns the common prefix of the extracted files.

  Paths in |to_extract| should be relative to the output directory.
  """
  zipped_paths = z.namelist()
  output_dir = os.path.commonprefix(zipped_paths)
  for f in to_extract:
    path = os.path.join(output_dir, f)
    if path in zipped_paths:
      z.extract(path, path=dst)
  return os.path.join(dst, output_dir)


def _PrintAndWriteToFile(logfile, s, *args, **kwargs):
  """Write and print |s| thottling output if |s| is a large list."""
  if isinstance(s, basestring):
    s = s.format(*args, **kwargs)
    print s
    logfile.write('%s\n' % s)
  else:
    for l in s[:_DIFF_DETAILS_LINES_THRESHOLD]:
      print l
    if len(s) > _DIFF_DETAILS_LINES_THRESHOLD:
      print '\nOutput truncated, see %s for more.' % logfile.name
    logfile.write('\n'.join(s))


@contextmanager
def _TmpCopyBinarySizeDir():
  """Recursively copy files to a temp dir and yield supersize path."""
  # Needs to be at same level of nesting as the real //tools/binary_size
  # since supersize uses this to find d3 in //third_party.
  tmp_dir = tempfile.mkdtemp(dir=_SRC_ROOT)
  try:
    bs_dir = os.path.join(tmp_dir, 'binary_size')
    shutil.copytree(_BINARY_SIZE_DIR, bs_dir)
    yield os.path.join(bs_dir, 'supersize')
  finally:
    shutil.rmtree(tmp_dir)


def _CurrentGitHash(subrepo):
  return _GitCmd(['rev-parse', 'HEAD'], subrepo)


def _SetRestoreFunc(subrepo):
  branch = _GitCmd(['rev-parse', '--abbrev-ref', 'HEAD'], subrepo)
  atexit.register(lambda: _GitCmd(['checkout', branch], subrepo))


def main():
  parser = argparse.ArgumentParser(
      description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument('--archive-directory',
                      default=_DEFAULT_ARCHIVE_DIR,
                      help='Where results are stored.')
  parser.add_argument('rev',
                      help='Find binary size bloat for this commit.')
  parser.add_argument('--reference-rev',
                      help='Older rev to diff against. If not supplied, '
                           'the previous commit to rev will be used.')
  parser.add_argument('--all',
                      action='store_true',
                      help='Build/download all revs from --reference-rev to '
                           'rev and diff the contiguous revisions.')
  parser.add_argument('--include-slow-options',
                      action='store_true',
                      help='Run some extra steps that take longer to complete. '
                           'This includes apk-patch-size estimation and '
                           'static-initializer counting.')
  parser.add_argument('--cloud',
                      action='store_true',
                      help='Download build artifacts from perf builders '
                      '(Googlers only).')
  parser.add_argument('--depot-tools-path',
                      help='Custom path to depot tools. Needed for --cloud if '
                           'depot tools isn\'t in your PATH.')
  parser.add_argument('--subrepo',
                      help='Specify a subrepo directory to use. Gclient sync '
                           'will be skipped if this option is used and all git '
                           'commands will be executed from the subrepo '
                           'directory. This option doesn\'t work with --cloud.')
  parser.add_argument('-v',
                      '--verbose',
                      action='store_true',
                      help='Show  commands executed, extra debugging output'
                           ', and Ninja/GN output')

  build_group = parser.add_argument_group('ninja arguments')
  build_group.add_argument('-j',
                           dest='max_jobs',
                           help='Run N jobs in parallel.')
  build_group.add_argument('-l',
                           dest='max_load_average',
                           help='Do not start new jobs if the load average is '
                           'greater than N.')
  build_group.add_argument('--no-goma',
                           action='store_false',
                           dest='use_goma',
                           default=True,
                           help='Do not use goma when building with ninja.')
  build_group.add_argument('--target-os',
                           default='android',
                           choices=['android', 'linux'],
                           help='target_os gn arg. Default: android.')
  build_group.add_argument('--output-directory',
                           default=_DEFAULT_OUT_DIR,
                           help='ninja output directory. '
                                'Default: %s.' % _DEFAULT_OUT_DIR)
  build_group.add_argument('--enable-chrome-android-internal',
                           action='store_true',
                           help='Allow downstream targets to be built.')
  build_group.add_argument('--target',
                           default=_DEFAULT_ANDROID_TARGET,
                           help='GN APK target to build. Ignored for Linux. '
                                'Default %s.' % _DEFAULT_ANDROID_TARGET)
  if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()
  args = parser.parse_args()
  log_level = logging.DEBUG if args.verbose else logging.INFO
  logging.basicConfig(level=log_level,
                      format='%(levelname).1s %(relativeCreated)6d %(message)s')
  build = _BuildHelper(args)
  if build.IsCloud():
    if args.subrepo:
      parser.error('--subrepo doesn\'t work with --cloud')
    if build.IsLinux():
      parser.error('--target-os linux doesn\'t work with --cloud because map '
                   'files aren\'t generated by builders (crbug.com/716209).')

  subrepo = args.subrepo or _SRC_ROOT
  if not build.IsCloud():
    _EnsureDirectoryClean(subrepo)
    _SetRestoreFunc(subrepo)

  if build.IsLinux():
    _VerifyUserAccepts('Linux diffs have known deficiencies (crbug/717550).')

  rev, reference_rev = _ValidateRevs(
      args.rev, args.reference_rev or args.rev + '^', subrepo)
  revs = _GenerateRevList(rev, reference_rev, args.all, subrepo)
  with _TmpCopyBinarySizeDir() as supersize_path:
    diffs = [NativeDiff(build.size_name, supersize_path)]
    if build.IsAndroid():
      diffs +=  [
          ResourceSizesDiff(
              build.apk_name, slow_options=args.include_slow_options)
      ]
    diff_mngr = _DiffArchiveManager(
        revs, args.archive_directory, diffs, build, subrepo)
    consecutive_failures = 0
    for i, archive in enumerate(diff_mngr.IterArchives()):
      if archive.Exists():
        step = 'download' if build.IsCloud() else 'build'
        logging.info('Found matching metadata for %s, skipping %s step.',
                     archive.rev, step)
      else:
        if build.IsCloud():
          _DownloadBuildArtifacts(
              archive, build, supersize_path, args.depot_tools_path)
        else:
          build_failure = _SyncAndBuild(archive, build, subrepo)
          if build_failure:
            logging.info(
                'Build failed for %s, diffs using this rev will be skipped.',
                archive.rev)
            consecutive_failures += 1
            if consecutive_failures > _ALLOWED_CONSECUTIVE_FAILURES:
              _Die('%d builds failed in a row, last failure was %s.',
                   consecutive_failures, archive.rev)
          else:
            archive.ArchiveBuildResults(supersize_path)
            consecutive_failures = 0

      if i != 0:
        diff_mngr.MaybeDiff(i - 1, i)

    diff_mngr.Summarize()


if __name__ == '__main__':
  sys.exit(main())


#!/usr/bin/env python
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Run Performance Test Bisect Tool

This script is used by a try bot to run the bisect script with the parameters
specified in the bisect config file. It checks out a copy of the depot in
a subdirectory 'bisect' of the working directory provided, annd runs the
bisect scrip there.
"""

import json
import optparse
import os
import platform
import re
import shlex
import subprocess
import sys
import traceback

from auto_bisect import bisect_perf_regression
from auto_bisect import bisect_utils
from auto_bisect import math_utils
from auto_bisect import source_control

CROS_BOARD_ENV = 'BISECT_CROS_BOARD'
CROS_IP_ENV = 'BISECT_CROS_IP'
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
SRC_DIR = os.path.join(SCRIPT_DIR, os.path.pardir)
BISECT_CONFIG_PATH = os.path.join(SCRIPT_DIR, 'auto_bisect', 'bisect.cfg')
RUN_TEST_CONFIG_PATH = os.path.join(SCRIPT_DIR, 'run-perf-test.cfg')
WEBKIT_RUN_TEST_CONFIG_PATH = os.path.join(
    SRC_DIR, 'third_party', 'WebKit', 'Tools', 'run-perf-test.cfg')
BISECT_SCRIPT_DIR = os.path.join(SCRIPT_DIR, 'auto_bisect')

PERF_BENCHMARKS_PATH = 'tools/perf/benchmarks'
PERF_MEASUREMENTS_PATH = 'tools/perf/measurements'
BUILDBOT_BUILDERNAME = 'BUILDBOT_BUILDERNAME'
BENCHMARKS_JSON_FILE = 'benchmarks.json'

# This is used to identify tryjobs triggered by the commit queue.
_COMMIT_QUEUE_USERS = [
    '5071639625-1lppvbtck1morgivc6sq4dul7klu27sd@developer.gserviceaccount.com',
    'commit-bot@chromium.org']

class Goma(object):

  def __init__(self, path_to_goma):
    self._abs_path_to_goma = None
    self._abs_path_to_goma_file = None
    if not path_to_goma:
      return
    self._abs_path_to_goma = os.path.abspath(path_to_goma)
    filename = 'goma_ctl.bat' if os.name == 'nt' else 'goma_ctl.sh'
    self._abs_path_to_goma_file = os.path.join(self._abs_path_to_goma, filename)

  def __enter__(self):
    if self._HasGomaPath():
      self._SetupAndStart()
    return self

  def __exit__(self, *_):
    if self._HasGomaPath():
      self._Stop()

  def _HasGomaPath(self):
    return bool(self._abs_path_to_goma)

  def _SetupEnvVars(self):
    if os.name == 'nt':
      os.environ['CC'] = (os.path.join(self._abs_path_to_goma, 'gomacc.exe') +
          ' cl.exe')
      os.environ['CXX'] = (os.path.join(self._abs_path_to_goma, 'gomacc.exe') +
          ' cl.exe')
    else:
      os.environ['PATH'] = os.pathsep.join([self._abs_path_to_goma,
          os.environ['PATH']])

  def _SetupAndStart(self):
    """Sets up goma and launches it.

    Args:
      path_to_goma: Path to goma directory.

    Returns:
      True if successful."""
    self._SetupEnvVars()

    # Sometimes goma is lingering around if something went bad on a previous
    # run. Stop it before starting a new process. Can ignore the return code
    # since it will return an error if it wasn't running.
    self._Stop()

    if subprocess.call([self._abs_path_to_goma_file, 'start']):
      raise RuntimeError('Goma failed to start.')

  def _Stop(self):
    subprocess.call([self._abs_path_to_goma_file, 'stop'])


def _LoadConfigFile(config_file_path):
  """Attempts to load the specified config file as a module
  and grab the global config dict.

  Args:
    config_file_path: Path to the config file.

  Returns:
    If successful, returns the config dict loaded from the file. If no
    such dictionary could be loaded, returns the empty dictionary.
  """
  try:
    local_vars = {}
    execfile(config_file_path, local_vars)
    return local_vars['config']
  except Exception:
    print
    traceback.print_exc()
    print
    return {}


def _ValidateConfigFile(config_contents, required_parameters):
  """Validates the config file contents, checking whether all values are
  non-empty.

  Args:
    config_contents: A config dictionary.
    required_parameters: A list of parameters to check for.

  Returns:
    True if valid.
  """
  for parameter in required_parameters:
    if parameter not in config_contents:
      return False
    value = config_contents[parameter]
    if not value or type(value) is not str:
      return False
  return True


def _ValidatePerfConfigFile(config_contents):
  """Validates the perf config file contents.

  This is used when we're doing a perf try job, rather than a bisect.
  The config file is called run-perf-test.cfg by default.

  The parameters checked are the required parameters; any additional optional
  parameters won't be checked and validation will still pass.

  Args:
    config_contents: A config dictionary.

  Returns:
    True if valid.
  """
  return _ValidateConfigFile(config_contents, required_parameters=['command'])


def _ValidateBisectConfigFile(config_contents):
  """Validates the bisect config file contents.

  The parameters checked are the required parameters; any additional optional
  parameters won't be checked and validation will still pass.

  Args:
    config_contents: A config dictionary.

  Returns:
    True if valid.
  """
  return _ValidateConfigFile(
      config_contents,
      required_parameters=['command', 'good_revision', 'bad_revision'])


def _OutputFailedResults(text_to_print):
  bisect_utils.OutputAnnotationStepStart('Results - Failed')
  print
  print text_to_print
  print
  bisect_utils.OutputAnnotationStepClosed()


def _CreateBisectOptionsFromConfig(config):
  print config['command']
  opts_dict = {}
  opts_dict['command'] = config['command']
  opts_dict['metric'] = config.get('metric')

  if config['repeat_count']:
    opts_dict['repeat_test_count'] = int(config['repeat_count'])

  if config['truncate_percent']:
    opts_dict['truncate_percent'] = int(config['truncate_percent'])

  if config['max_time_minutes']:
    opts_dict['max_time_minutes'] = _Clamp(
        int(config['max_time_minutes']), low=1, high=60)

  if config.has_key('use_goma'):
    opts_dict['use_goma'] = config['use_goma']
  if config.has_key('goma_dir'):
    opts_dict['goma_dir'] = config['goma_dir']

  if config.has_key('improvement_direction'):
    opts_dict['improvement_direction'] = int(config['improvement_direction'])

  if config.has_key('required_initial_confidence'):
    opts_dict['required_initial_confidence'] = float(
        config['required_initial_confidence'])

  if config.has_key('target_arch'):
    opts_dict['target_arch'] = config['target_arch']

  if config.has_key('bug_id') and str(config['bug_id']).isdigit():
    opts_dict['bug_id'] = config['bug_id']

  if config.has_key('try_job_id'):
    opts_dict['try_job_id'] = config['try_job_id']

  opts_dict['build_preference'] = 'ninja'
  opts_dict['output_buildbot_annotations'] = True

  if '--browser=cros' in config['command']:
    opts_dict['target_platform'] = 'cros'

    if os.environ[CROS_BOARD_ENV] and os.environ[CROS_IP_ENV]:
      opts_dict['cros_board'] = os.environ[CROS_BOARD_ENV]
      opts_dict['cros_remote_ip'] = os.environ[CROS_IP_ENV]
    else:
      raise RuntimeError('CrOS build selected, but BISECT_CROS_IP or'
          'BISECT_CROS_BOARD undefined.')
  elif 'android' in config['command']:
    if 'android-chromium' in config['command']:
      opts_dict['target_platform'] = 'android'
    elif 'android-chrome' in config['command']:
      opts_dict['target_platform'] = 'android-chrome'
    else:
      opts_dict['target_platform'] = 'android'

  return bisect_perf_regression.BisectOptions.FromDict(opts_dict)


def _Clamp(n, low, high):
  """Clamps a value to a range."""
  return min(high, max(low, n))


def _ParseCloudLinksFromOutput(output):
  html_results_pattern = re.compile(
      r'\s(?P<VALUES>http://storage.googleapis.com/' +
          'chromium-telemetry/html-results/results-[a-z0-9-_]+)\s',
      re.MULTILINE)
  profiler_pattern = re.compile(
      r'\s(?P<VALUES>https://console.developers.google.com/' +
          'm/cloudstorage/b/[a-z-]+/o/profiler-[a-z0-9-_.]+)\s',
      re.MULTILINE)

  results = {
      'html-results': html_results_pattern.findall(output),
      'profiler': profiler_pattern.findall(output),
  }

  return results


def _ParseAndOutputCloudLinks(
    results_without_patch, results_with_patch, annotations_dict):
  cloud_links_without_patch = _ParseCloudLinksFromOutput(
      results_without_patch[2])
  cloud_links_with_patch = _ParseCloudLinksFromOutput(
      results_with_patch[2])

  cloud_file_link = (cloud_links_without_patch['html-results'][0]
      if cloud_links_without_patch['html-results'] else '')

  profiler_file_links_with_patch = cloud_links_with_patch['profiler']
  profiler_file_links_without_patch = cloud_links_without_patch['profiler']

  # Calculate the % difference in the means of the 2 runs.
  percent_diff_in_means = None
  std_err = None
  if (results_with_patch[0].has_key('mean') and
      results_with_patch[0].has_key('values')):
    percent_diff_in_means = (results_with_patch[0]['mean'] /
        max(0.0001, results_without_patch[0]['mean'])) * 100.0 - 100.0
    std_err = math_utils.PooledStandardError(
        [results_with_patch[0]['values'], results_without_patch[0]['values']])

  if percent_diff_in_means is not None and std_err is not None:
    bisect_utils.OutputAnnotationStepStart('Results - %.02f +- %0.02f delta' %
        (percent_diff_in_means, std_err))
    print ' %s %s %s' % (''.center(10, ' '), 'Mean'.center(20, ' '),
        'Std. Error'.center(20, ' '))
    print ' %s %s %s' % ('Patch'.center(10, ' '),
        ('%.02f' % results_with_patch[0]['mean']).center(20, ' '),
        ('%.02f' % results_with_patch[0]['std_err']).center(20, ' '))
    print ' %s %s %s' % ('No Patch'.center(10, ' '),
        ('%.02f' % results_without_patch[0]['mean']).center(20, ' '),
        ('%.02f' % results_without_patch[0]['std_err']).center(20, ' '))
    if cloud_file_link:
      bisect_utils.OutputAnnotationStepLink('HTML Results', cloud_file_link)
    bisect_utils.OutputAnnotationStepClosed()
  elif cloud_file_link:
    bisect_utils.OutputAnnotationStepLink('HTML Results', cloud_file_link)

  if profiler_file_links_with_patch and profiler_file_links_without_patch:
    for i in xrange(len(profiler_file_links_with_patch)):
      bisect_utils.OutputAnnotationStepLink(
          '%s[%d]' % (annotations_dict.get('profiler_link1'), i),
          profiler_file_links_with_patch[i])
    for i in xrange(len(profiler_file_links_without_patch)):
      bisect_utils.OutputAnnotationStepLink(
          '%s[%d]' % (annotations_dict.get('profiler_link2'), i),
          profiler_file_links_without_patch[i])


def _ResolveRevisionsFromConfig(config):
  if not 'good_revision' in config and not 'bad_revision' in config:
    return (None, None)

  bad_revision = source_control.ResolveToRevision(
      config['bad_revision'], 'chromium', bisect_utils.DEPOT_DEPS_NAME, 100)
  if not bad_revision:
    raise RuntimeError('Failed to resolve [%s] to git hash.',
        config['bad_revision'])
  good_revision = source_control.ResolveToRevision(
      config['good_revision'], 'chromium', bisect_utils.DEPOT_DEPS_NAME, -100)
  if not good_revision:
    raise RuntimeError('Failed to resolve [%s] to git hash.',
        config['good_revision'])

  return (good_revision, bad_revision)


def _GetStepAnnotationStringsDict(config):
  if 'good_revision' in config and 'bad_revision' in config:
    return {
        'build1': 'Building [%s]' % config['good_revision'],
        'build2': 'Building [%s]' % config['bad_revision'],
        'run1': 'Running [%s]' % config['good_revision'],
        'run2': 'Running [%s]' % config['bad_revision'],
        'sync1': 'Syncing [%s]' % config['good_revision'],
        'sync2': 'Syncing [%s]' % config['bad_revision'],
        'results_label1': config['good_revision'],
        'results_label2': config['bad_revision'],
        'profiler_link1': 'Profiler Data - %s' % config['good_revision'],
        'profiler_link2': 'Profiler Data - %s' % config['bad_revision'],
    }
  else:
    return {
        'build1': 'Building With Patch',
        'build2': 'Building Without Patch',
        'run1': 'Running With Patch',
        'run2': 'Running Without Patch',
        'results_label1': 'Patch',
        'results_label2': 'ToT',
        'profiler_link1': 'With Patch - Profiler Data',
        'profiler_link2': 'Without Patch - Profiler Data',
    }


def _RunBuildStepForPerformanceTest(bisect_instance,
                                    build_string,
                                    sync_string,
                                    revision):
  if revision:
    bisect_utils.OutputAnnotationStepStart(sync_string)
    if not source_control.SyncToRevision(revision, 'gclient'):
      raise RuntimeError('Failed [%s].' % sync_string)
    bisect_utils.OutputAnnotationStepClosed()

  bisect_utils.OutputAnnotationStepStart(build_string)

  if bisect_utils.RunGClient(['runhooks']):
    raise RuntimeError('Failed to run gclient runhooks')

  if not bisect_instance.ObtainBuild('chromium'):
    raise RuntimeError('Patched version failed to build.')

  bisect_utils.OutputAnnotationStepClosed()


def _RunCommandStepForPerformanceTest(bisect_instance,
                                      opts,
                                      reset_on_first_run,
                                      upload_on_last_run,
                                      results_label,
                                      run_string):
  bisect_utils.OutputAnnotationStepStart(run_string)

  results = bisect_instance.RunPerformanceTestAndParseResults(
      opts.command,
      opts.metric,
      reset_on_first_run=reset_on_first_run,
      upload_on_last_run=upload_on_last_run,
      results_label=results_label,
      allow_flakes=False)

  if results[1]:
    raise RuntimeError('Patched version failed to run performance test.')

  bisect_utils.OutputAnnotationStepClosed()

  return results


def _RunPerformanceTest(config):
  """Runs a performance test with and without the current patch.

  Args:
    config: Contents of the config file, a dictionary.

  Attempts to build and run the current revision with and without the
  current patch, with the parameters passed in.
  """
  # Bisect script expects to be run from the src directory
  os.chdir(SRC_DIR)

  opts = _CreateBisectOptionsFromConfig(config)
  revisions = _ResolveRevisionsFromConfig(config)
  annotations_dict = _GetStepAnnotationStringsDict(config)
  b = bisect_perf_regression.BisectPerformanceMetrics(opts, os.getcwd())

  _RunBuildStepForPerformanceTest(b,
                                  annotations_dict.get('build1'),
                                  annotations_dict.get('sync1'),
                                  revisions[0])

  results_with_patch = _RunCommandStepForPerformanceTest(
      b, opts, True, True, annotations_dict['results_label1'],
      annotations_dict['run1'])

  bisect_utils.OutputAnnotationStepStart('Reverting Patch')
  # TODO: When this is re-written to recipes, this should use bot_update's
  # revert mechanism to fully revert the client. But for now, since we know that
  # the perf try bot currently only supports src/ and src/third_party/WebKit, we
  # simply reset those two directories.
  bisect_utils.CheckRunGit(['reset', '--hard'])
  bisect_utils.CheckRunGit(['reset', '--hard'],
                           os.path.join('third_party', 'WebKit'))
  bisect_utils.OutputAnnotationStepClosed()

  _RunBuildStepForPerformanceTest(b,
                                  annotations_dict.get('build2'),
                                  annotations_dict.get('sync2'),
                                  revisions[1])

  results_without_patch = _RunCommandStepForPerformanceTest(
      b, opts, False, True, annotations_dict['results_label2'],
      annotations_dict['run2'])

  # Find the link to the cloud stored results file.
  _ParseAndOutputCloudLinks(
      results_without_patch, results_with_patch, annotations_dict)


def _SetupAndRunPerformanceTest(config, path_to_goma, is_cq_tryjob=False):
  """Attempts to build and run the current revision with and without the
  current patch, with the parameters passed in.

  Args:
    config: The config read from run-perf-test.cfg.
    path_to_goma: Path to goma directory.
    is_cq_tryjob: Whether or not the try job was initiated by commit queue.

  Returns:
    An exit code: 0 on success, otherwise 1.
  """
  if platform.release() == 'XP':
    print 'Windows XP is not supported for perf try jobs because it lacks '
    print 'goma support. Please refer to crbug.com/330900.'
    return 1
  try:
    with Goma(path_to_goma) as _:
      config['use_goma'] = bool(path_to_goma)
      if config['use_goma']:
        config['goma_dir'] = os.path.abspath(path_to_goma)
      if not is_cq_tryjob:
        _RunPerformanceTest(config)
      else:
        return _RunBenchmarksForCommitQueue(config)
    return 0
  except RuntimeError, e:
    bisect_utils.OutputAnnotationStepFailure()
    bisect_utils.OutputAnnotationStepClosed()
    _OutputFailedResults('Error: %s' % e.message)
    return 1


def _RunBisectionScript(
    config, working_directory, path_to_goma, path_to_extra_src, dry_run):
  """Attempts to execute the bisect script with the given parameters.

  Args:
    config: A dict containing the parameters to pass to the script.
    working_directory: A working directory to provide to the bisect script,
      where it will store it's own copy of the depot.
    path_to_goma: Path to goma directory.
    path_to_extra_src: Path to extra source file.
    dry_run: Do a dry run, skipping sync, build, and performance testing steps.

  Returns:
    An exit status code: 0 on success, otherwise 1.
  """
  _PrintConfigStep(config)

  # Construct the basic command with all necessary arguments.
  cmd = [
      'python',
      os.path.join(BISECT_SCRIPT_DIR, 'bisect_perf_regression.py'),
      '--command', config['command'],
      '--good_revision', config['good_revision'],
      '--bad_revision', config['bad_revision'],
      '--working_directory', working_directory,
      '--output_buildbot_annotations'
  ]

  # Add flags for any optional config parameters if given in the config.
  options = [
      ('metric', '--metric'),
      ('repeat_count', '--repeat_test_count'),
      ('truncate_percent', '--truncate_percent'),
      ('max_time_minutes', '--max_time_minutes'),
      ('bisect_mode', '--bisect_mode'),
      ('improvement_direction', '--improvement_direction'),
      ('bug_id', '--bug_id'),
      ('try_job_id', '--try_job_id'),
      ('builder_type', '--builder_type'),
      ('target_arch', '--target_arch'),
      ('required_initial_confidence', '--required_initial_confidence'),
  ]
  for config_key, flag in options:
    if config.has_key(config_key):
      cmd.extend([flag, config[config_key]])

  cmd.extend(['--build_preference', 'ninja'])

  # Possibly set the target platform name based on the browser name in a
  # Telemetry command.
  if 'android-chromium' in config['command']:
    cmd.extend(['--target_platform', 'android'])
  elif 'android-chrome' in config['command']:
    cmd.extend(['--target_platform', 'android-chrome'])
  elif 'android' in config['command']:
    cmd.extend(['--target_platform', 'android'])

  if path_to_goma:
    # For Windows XP platforms, goma service is not supported.
    # Moreover we don't compile chrome when gs_bucket flag is set instead
    # use builds archives, therefore ignore goma service for Windows XP.
    # See http://crbug.com/330900.
    if platform.release() == 'XP':
      print ('Goma doesn\'t have a win32 binary, therefore it is not supported '
             'on Windows XP platform. Please refer to crbug.com/330900.')
      path_to_goma = None
    cmd.append('--use_goma')
    cmd.append('--goma_dir')
    cmd.append(os.path.abspath(path_to_goma))

  if path_to_extra_src:
    cmd.extend(['--extra_src', path_to_extra_src])

  if dry_run:
    cmd.extend([
        '--debug_ignore_build',
        '--debug_ignore_sync',
        '--debug_ignore_perf_test'
    ])

  cmd = [str(c) for c in cmd]

  with Goma(path_to_goma) as _:
    return_code = subprocess.call(cmd)

  if return_code:
    print ('Error: bisect_perf_regression.py returned with error %d\n'
           % return_code)

  return return_code


def _PrintConfigStep(config):
  """Prints out the given config, along with Buildbot annotations."""
  bisect_utils.OutputAnnotationStepStart('Config')
  print
  for k, v in config.iteritems():
    print '  %s : %s' % (k, v)
  print
  bisect_utils.OutputAnnotationStepClosed()


def _GetBrowserType(bot_platform):
  """Gets the browser type to be used in the run benchmark command."""
  if bot_platform == 'android':
    return 'android-chromium'
  elif 'x64' in bot_platform:
    return 'release_x64'

  return 'release'



def _GuessTelemetryTestCommand(bot_platform, test_name=None):
  """Creates a Telemetry benchmark command based on bot and test name."""
  command = []
  # On Windows, Python scripts should be prefixed with the python command.
  if bot_platform == 'win':
    command.append('python')
  command.append('tools/perf/run_benchmark')
  command.append('-v')
  command.append('--browser=%s' % _GetBrowserType(bot_platform))
  if test_name:
    command.append(test_name)

  return ' '.join(command)


def _GetConfigBasedOnPlatform(config, bot_name, test_name):
  """Generates required options to create BisectPerformanceMetrics instance."""
  opts_dict = {
      'command': _GuessTelemetryTestCommand(bot_name, test_name),
      'target_arch': 'x64' if 'x64' in bot_name else 'ia32',
      'build_preference': 'ninja',
      'output_buildbot_annotations': True,
      'repeat_test_count': 1,
      'bisect_mode': bisect_utils.BISECT_MODE_RETURN_CODE,
  }

  if 'use_goma' in config:
    opts_dict['use_goma'] = config['use_goma']
  if 'goma_dir' in config:
    opts_dict['goma_dir'] = config['goma_dir']
  if 'android-chromium' in opts_dict['command']:
    opts_dict['target_platform'] = 'android'

  return bisect_perf_regression.BisectOptions.FromDict(opts_dict)


def _GetModifiedFilesFromPatch(cwd=None):
  """Gets list of files modified in the current patch."""
  log_output = bisect_utils.CheckRunGit(
      ['diff', '--no-ext-diff', '--name-only', 'HEAD~1'], cwd=cwd)
  modified_files = log_output.split()
  return modified_files


def _GetAffectedBenchmarkModuleNames():
  """Gets list of modified benchmark files under tools/perf/benchmarks."""
  all_affected_files = _GetModifiedFilesFromPatch()
  modified_benchmarks = []
  for affected_file in all_affected_files:
    if (affected_file.startswith(PERF_BENCHMARKS_PATH) or
        affected_file.startswith(PERF_MEASUREMENTS_PATH)):
      benchmark = os.path.basename(os.path.splitext(affected_file)[0])
      modified_benchmarks.append(benchmark)
  return modified_benchmarks


def _ListAvailableBenchmarks(bot_platform):
  """Gets all available benchmarks names as a list."""
  browser_type =  _GetBrowserType(bot_platform)
  if os.path.exists(BENCHMARKS_JSON_FILE):
    os.remove(BENCHMARKS_JSON_FILE)
  command = []
  if 'win' in bot_platform:
    command.append('python')
  command.append('tools/perf/run_benchmark')
  command.extend([
      'list',
      '--browser',
      browser_type,
      '--json-output',
      BENCHMARKS_JSON_FILE])
  try:
    output, return_code = bisect_utils.RunProcessAndRetrieveOutput(
        command=command, cwd=SRC_DIR)
    if return_code:
      raise RuntimeError('Something went wrong while listing benchmarks. '
            'Please review the command line: %s.\nERROR: [%s]' %
            (' '.join(command), output))
    with open(BENCHMARKS_JSON_FILE) as tests_json:
      tests_data = json.load(tests_json)
      if tests_data.get('steps'):
        return tests_data.get('steps').keys()
  finally:
    try:
      if os.path.exists(BENCHMARKS_JSON_FILE):
        os.remove(BENCHMARKS_JSON_FILE)
    except OSError as e:
      if e.errno != errno.ENOENT:
        raise
  return None


def _OutputOverallResults(results):
  """Creates results step and prints results on buildbot job."""
  test_status = all(current_value == True for current_value in results.values())
  bisect_utils.OutputAnnotationStepStart(
      'Results - %s' % ('Passed' if test_status else 'Failed'))
  print
  print 'Results of benchmarks:'
  print
  for benchmark, result in results.iteritems():
    print '%s: %s' % (benchmark, 'Passed' if result else 'Failed')
  if not test_status:
    bisect_utils.OutputAnnotationStepFailure()
  bisect_utils.OutputAnnotationStepClosed()
  # Returns 0 for success and 1 for failure.
  return 0 if test_status else 1


def _RunBenchmark(bisect_instance, opts, bot_name, benchmark_name):
  """Runs a Telemetry benchmark."""
  bisect_utils.OutputAnnotationStepStart(benchmark_name)
  command_to_run = _GuessTelemetryTestCommand(bot_name, benchmark_name)
  args = shlex.split(command_to_run, posix=not bisect_utils.IsWindowsHost())
  output, return_code = bisect_utils.RunProcessAndRetrieveOutput(args, SRC_DIR)
  # A value other than 0 indicates that the test couldn't be run, and results
  # should also include an error message.
  if return_code:
    print ('Error: Something went wrong running the benchmark: %s.'
           'Please review the command line:%s\n\n%s' %
           (benchmark_name, command_to_run, output))
    bisect_utils.OutputAnnotationStepFailure()
  print output
  bisect_utils.OutputAnnotationStepClosed()
  # results[1] contains the return code from subprocess that executes test
  # command, On successful test run it contains 0 otherwise any non-zero value.
  return return_code == 0


def _RunBenchmarksForCommitQueue(config):
  """Runs Telemetry benchmark for the commit queue."""
  os.chdir(SRC_DIR)
  # To determine the bot platform by reading buildbot name from environment
  # variable.
  bot_name = os.environ.get(BUILDBOT_BUILDERNAME)
  if not bot_name:
    bot_name = sys.platform
  bot_name = bot_name.split('_')[0]

  affected_benchmarks = _GetAffectedBenchmarkModuleNames()
  # Abort if there are no changes to benchmark any existing benchmark files.
  if not affected_benchmarks:
    bisect_utils.OutputAnnotationStepStart('Results')
    print
    print ('There are no modification to Telemetry benchmarks,'
           ' aborting the try job.')
    bisect_utils.OutputAnnotationStepClosed()
    return 0

  # Bisect script expects to be run from the src directory
  # Gets required options inorder to create BisectPerformanceMetrics instance.
  # Since command is a required arg in BisectPerformanceMetrics, we just create
  # a dummy command for now.
  opts = _GetConfigBasedOnPlatform(config, bot_name, test_name='')
  annotations_dict = _GetStepAnnotationStringsDict(config)
  b = bisect_perf_regression.BisectPerformanceMetrics(opts, os.getcwd())
  _RunBuildStepForPerformanceTest(b,
                                  annotations_dict.get('build1'),
                                  annotations_dict.get('sync1'),
                                  None)
  available_benchmarks = _ListAvailableBenchmarks(bot_name)
  overall_results = {}
  for affected_benchmark in affected_benchmarks:
    for benchmark in available_benchmarks:
      if (benchmark.startswith(affected_benchmark) and
          not benchmark.endswith('reference')):
        overall_results[benchmark] = _RunBenchmark(b, opts, bot_name, benchmark)

  return _OutputOverallResults(overall_results)


def _OptionParser():
  """Returns the options parser for run-bisect-perf-regression.py."""

  def ConvertJson(option, _, value, parser):
    """Provides an OptionParser callback to unmarshal a JSON string."""
    setattr(parser.values, option.dest, json.loads(value))

  usage = ('%prog [options] [-- chromium-options]\n'
           'Used by a try bot to run the bisection script using the parameters'
           ' provided in the auto_bisect/bisect.cfg file.')
  parser = optparse.OptionParser(usage=usage)
  parser.add_option('-w', '--working_directory',
                    type='str',
                    help='A working directory to supply to the bisection '
                    'script, which will use it as the location to checkout '
                    'a copy of the chromium depot.')
  parser.add_option('-p', '--path_to_goma',
                    type='str',
                    help='Path to goma directory. If this is supplied, goma '
                    'builds will be enabled.')
  parser.add_option('--path_to_config',
                    type='str',
                    help='Path to the config file to use. If this is supplied, '
                    'the bisect script will use this to override the default '
                    'config file path. The script will attempt to load it '
                    'as a bisect config first, then a perf config.')
  parser.add_option('--extra_src',
                    type='str',
                    help='Path to extra source file. If this is supplied, '
                    'bisect script will use this to override default behavior.')
  parser.add_option('--dry_run',
                    action="store_true",
                    help='The script will perform the full bisect, but '
                    'without syncing, building, or running the performance '
                    'tests.')
  # This argument is passed by buildbot to supply build properties to the bisect
  # script. Note: Don't change "--build-properties" property name.
  parser.add_option('--build-properties', action='callback',
                    dest='build_properties',
                    callback=ConvertJson, type='string',
                    nargs=1, default={},
                    help='build properties in JSON format')

  return parser


def main():
  """Entry point for run-bisect-perf-regression.py.

  Reads the config file, and then tries to either bisect a regression or
  just run a performance test, depending on the particular config parameters
  specified in the config file.
  """
  parser = _OptionParser()
  opts, _ = parser.parse_args()

  # Use the default config file path unless one was specified.
  config_path = BISECT_CONFIG_PATH
  if opts.path_to_config:
    config_path = opts.path_to_config
  config = _LoadConfigFile(config_path)

  # Check if the config is valid for running bisect job.
  config_is_valid = _ValidateBisectConfigFile(config)

  if config and config_is_valid:
    if not opts.working_directory:
      print 'Error: missing required parameter: --working_directory\n'
      parser.print_help()
      return 1

    return _RunBisectionScript(
        config, opts.working_directory, opts.path_to_goma, opts.extra_src,
        opts.dry_run)

  # If it wasn't valid for running a bisect, then maybe the user wanted
  # to run a perf test instead of a bisect job. Try reading any possible
  # perf test config files.
  perf_cfg_files = [RUN_TEST_CONFIG_PATH, WEBKIT_RUN_TEST_CONFIG_PATH]
  for current_perf_cfg_file in perf_cfg_files:
    if opts.path_to_config:
      path_to_perf_cfg = opts.path_to_config
    else:
      path_to_perf_cfg = os.path.join(
          os.path.abspath(os.path.dirname(sys.argv[0])),
          current_perf_cfg_file)

    config = _LoadConfigFile(path_to_perf_cfg)
    config_is_valid = _ValidatePerfConfigFile(config)

    if config and config_is_valid:
      return _SetupAndRunPerformanceTest(config, opts.path_to_goma)

  # If there are no changes to config file, then check if the request is
  # from the commit queue, if so then run the modified Telemetry benchmarks for
  # the patch.
  if opts.build_properties.get('requester') in _COMMIT_QUEUE_USERS:
    return _SetupAndRunPerformanceTest(
        config={}, path_to_goma=opts.path_to_goma, is_cq_tryjob=True)

  print ('Error: Could not load config file. Double check your changes to '
         'auto_bisect/bisect.cfg or run-perf-test.cfg for syntax errors.\n')
  return 1


if __name__ == '__main__':
  sys.exit(main())

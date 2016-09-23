# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import json
import logging
import os
import platform
import re
import subprocess
import urllib2


from core import path_util

from telemetry import benchmark
from telemetry import decorators
from telemetry.core import discover
from telemetry.util import command_line
from telemetry.util import matching


# Unsupported Perf bisect bots.
EXCLUDED_BOTS = {
    'win_xp_perf_bisect',  # Goma issues: crbug.com/330900
    'win_perf_bisect_builder',
    'win64_nv_tester',
    'winx64_bisect_builder',
    'linux_perf_bisect_builder',
    'mac_perf_bisect_builder',
    'android_perf_bisect_builder',
    'android_arm64_perf_bisect_builder',
    # Bisect FYI bots are not meant for testing actual perf regressions.
    # Hardware configuration on these bots is different from actual bisect bot
    # and these bots runs E2E integration tests for auto-bisect
    # using dummy benchmarks.
    'linux_fyi_perf_bisect',
    'mac_fyi_perf_bisect',
    'win_fyi_perf_bisect',
    'winx64_fyi_perf_bisect',
    # CQ bots on tryserver.chromium.perf
    'android_s5_perf_cq',
    'winx64_10_perf_cq',
    'mac_retina_perf_cq',
    'linux_perf_cq',
}

INCLUDE_BOTS = [
    'all',
    'all-win',
    'all-mac',
    'all-linux',
    'all-android'
]

# Default try bot to use incase builbot is unreachable.
DEFAULT_TRYBOTS = [
    'linux_perf_bisect',
    'mac_10_11_perf_bisect',
    'winx64_10_perf_bisect',
    'android_s5_perf_bisect',
]

CHROMIUM_SRC_PATH = path_util.GetChromiumSrcDir()

assert not set(DEFAULT_TRYBOTS) & set(EXCLUDED_BOTS), (
    'A trybot cannot present in both Default as well as Excluded bots lists.')


class TrybotError(Exception):

  def __str__(self):
    return '(ERROR) Perf Try Job: %s' % self.args[0]


def _GetTrybotList(builders):
  builders = ['%s' % bot.replace('_perf_bisect', '').replace('_', '-')
              for bot in builders]
  builders.extend(INCLUDE_BOTS)
  return sorted(builders)


def _GetBotPlatformFromTrybotName(trybot_name):
  os_names = ['linux', 'android', 'mac', 'win']
  try:
    return next(b for b in os_names if b in trybot_name)
  except StopIteration:
    raise TrybotError('Trybot "%s" unsupported for tryjobs.' % trybot_name)


def _GetBuilderNames(trybot_name, builders):
  """Return platform and its available bot name as dictionary."""
  os_names = ['linux', 'android', 'mac', 'win']
  if 'all' not in trybot_name:
    bot = ['%s_perf_bisect' % trybot_name.replace('-', '_')]
    bot_platform = _GetBotPlatformFromTrybotName(trybot_name)
    if 'x64' in trybot_name:
      bot_platform += '-x64'
    return {bot_platform: bot}

  platform_and_bots = {}
  for os_name in os_names:
    platform_and_bots[os_name] = [bot for bot in builders if os_name in bot]

  # Special case for Windows x64, consider it as separate platform
  # config config should contain target_arch=x64 and --browser=release_x64.
  win_x64_bots = [
      win_bot for win_bot in platform_and_bots['win']
      if 'x64' in win_bot]
  # Separate out non x64 bits win bots
  platform_and_bots['win'] = list(
      set(platform_and_bots['win']) - set(win_x64_bots))
  platform_and_bots['win-x64'] = win_x64_bots

  if 'all-win' in trybot_name:
    return {'win': platform_and_bots['win'],
            'win-x64': platform_and_bots['win-x64']}
  if 'all-mac' in trybot_name:
    return {'mac': platform_and_bots['mac']}
  if 'all-android' in trybot_name:
    return {'android': platform_and_bots['android']}
  if 'all-linux' in trybot_name:
    return {'linux': platform_and_bots['linux']}

  return platform_and_bots


_GIT_CMD = 'git'


if platform.system() == 'Windows':
  # On windows, the git command is installed as 'git.bat'
  _GIT_CMD = 'git.bat'


def RunGit(cmd, msg_on_error='', ignore_return_code=False):
  """Runs the git command with the given arguments.

  Args:
    cmd: git command arguments.
    msg_on_error: Message to be displayed on git command error.
    ignore_return_code: Ignores the return code for git command.

  Returns:
    The output of the git command as string.

  Raises:
    TrybotError: This exception is raised when git command fails.
  """
  proc = subprocess.Popen(
      [_GIT_CMD] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output, err = proc.communicate()
  returncode = proc.poll()
  if returncode:
    if ignore_return_code:
      return None
    raise TrybotError('%s. \n%s' % (msg_on_error, err))

  return output


class Trybot(command_line.ArgParseCommand):
  """Run telemetry perf benchmark on trybot."""

  usage = 'botname benchmark_name [<benchmark run options>]'
  _builders = None

  def __init__(self):
    self._builder_names = None

  @classmethod
  def _GetBuilderList(cls):
    if not cls._builders:
      try:
        f = urllib2.urlopen(
            ('https://build.chromium.org/p/tryserver.chromium.perf/json/'
             'builders'),
            timeout=5)
      # In case of any kind of exception, allow tryjobs to use default trybots.
      # Possible exception are ssl.SSLError, urllib2.URLError,
      # socket.timeout, socket.error.
      except Exception:  # pylint: disable=broad-except
        # Incase of any exception return default trybots.
        print ('WARNING: Unable to reach builbot to retrieve trybot '
               'information, tryjob will use default trybots.')
        cls._builders = DEFAULT_TRYBOTS
      else:
        builders = json.loads(f.read()).keys()
        # Exclude unsupported bots like win xp and some dummy bots.
        cls._builders = [bot for bot in builders if bot not in EXCLUDED_BOTS]

    return cls._builders

  def _InitializeBuilderNames(self, trybot):
    self._builder_names = _GetBuilderNames(trybot, self._GetBuilderList())

  @classmethod
  def CreateParser(cls):
    parser = argparse.ArgumentParser(
        ('Run telemetry benchmarks on trybot. You can add all the benchmark '
         'options available except the --browser option'),
        formatter_class=argparse.RawTextHelpFormatter)
    return parser

  @classmethod
  def ProcessCommandLineArgs(cls, parser, options, extra_args, environment):
    del environment  # unused
    for arg in extra_args:
      if arg == '--browser' or arg.startswith('--browser='):
        parser.error('--browser=... is not allowed when running trybot.')
    all_benchmarks = discover.DiscoverClasses(
        start_dir=path_util.GetPerfBenchmarksDir(),
        top_level_dir=path_util.GetPerfDir(),
        base_class=benchmark.Benchmark).values()
    all_benchmark_names = [b.Name() for b in all_benchmarks]
    all_benchmarks_by_names = {b.Name(): b for b in all_benchmarks}
    benchmark_class = all_benchmarks_by_names.get(options.benchmark_name, None)
    if not benchmark_class:
      possible_benchmark_names = matching.GetMostLikelyMatchedObject(
          all_benchmark_names, options.benchmark_name)
      parser.error(
          'No benchmark named "%s". Do you mean any of those benchmarks '
          'below?\n%s' % (
              options.benchmark_name, '\n'.join(possible_benchmark_names)))
    is_benchmark_disabled, reason = cls.IsBenchmarkDisabledOnTrybotPlatform(
        benchmark_class, options.trybot)
    also_run_disabled_option = '--also-run-disabled-tests'
    if is_benchmark_disabled and also_run_disabled_option not in extra_args:
      parser.error('%s To run the benchmark on trybot anyway, add '
                   '%s option.' % (reason, also_run_disabled_option))

  @classmethod
  def IsBenchmarkDisabledOnTrybotPlatform(cls, benchmark_class, trybot_name):
    """Return whether benchmark will be disabled on trybot platform.

    Note that we cannot tell with certainty whether the benchmark will be
    disabled on the trybot platform since the disable logic in ShouldDisable()
    can be very dynamic and can only be verified on the trybot server platform.

    We are biased on the side of enabling the benchmark, and attempt to
    early discover whether the benchmark will be disabled as our best.

    It should never be the case that the benchmark will be enabled on the test
    platform but this method returns True.

    Returns:
      A tuple (is_benchmark_disabled, reason) whereas |is_benchmark_disabled| is
      a boolean that tells whether we are sure that the benchmark will be
      disabled, and |reason| is a string that shows the reason why we think the
      benchmark is disabled for sure.
    """
    benchmark_name = benchmark_class.Name()
    benchmark_disabled_strings = decorators.GetDisabledAttributes(
        benchmark_class)
    if 'all' in benchmark_disabled_strings:
      return True, 'Benchmark %s is disabled on all platform.' % benchmark_name
    if trybot_name == 'all':
      return False, ''
    trybot_platform = _GetBotPlatformFromTrybotName(trybot_name)
    if trybot_platform in benchmark_disabled_strings:
      return True, (
          "Benchmark %s is disabled on %s, and trybot's platform is %s." %
          (benchmark_name, ', '.join(benchmark_disabled_strings),
           trybot_platform))
    benchmark_enabled_strings = decorators.GetEnabledAttributes(benchmark_class)
    if (benchmark_enabled_strings and
        trybot_platform not in benchmark_enabled_strings and
        'all' not in benchmark_enabled_strings):
      return True, (
          "Benchmark %s is only enabled on %s, and trybot's platform is %s." %
          (benchmark_name, ', '.join(benchmark_enabled_strings),
           trybot_platform))
    if benchmark_class.ShouldDisable != benchmark.Benchmark.ShouldDisable:
      logging.warning(
          'Benchmark %s has ShouldDisable() method defined. If your trybot run '
          'does not produce any results, it is possible that the benchmark '
          'is disabled on the target trybot platform.', benchmark_name)
    return False, ''

  @classmethod
  def AddCommandLineArgs(cls, parser, environment):
    del environment  # unused
    available_bots = _GetTrybotList(cls._GetBuilderList())
    parser.add_argument(
        'trybot', choices=available_bots,
        help=('specify which bots to run telemetry benchmarks on. '
              ' Allowed values are:\n' + '\n'.join(available_bots)),
        metavar='<trybot name>')
    parser.add_argument(
        'benchmark_name', type=str,
        help=('specify which benchmark to run. To see all available benchmarks,'
              ' run `run_benchmark list`'),
        metavar='<benchmark name>')

  def Run(self, options, extra_args=None):
    """Sends a tryjob to a perf trybot.

    This creates a branch, telemetry-tryjob, switches to that branch, edits
    the bisect config, commits it, uploads the CL to rietveld, and runs a
    tryjob on the given bot.
    """
    if extra_args is None:
      extra_args = []
    self._InitializeBuilderNames(options.trybot)
    try:
      self._AttemptTryjob(CHROMIUM_SRC_PATH, options, extra_args)
    except TrybotError, error:
      print error
      return 1
    return 0

  def _GetPerfConfig(self, bot_platform, arguments):
    """Generates the perf config for try job.

    Args:
      bot_platform: Name of the platform to be generated.
      arguments: Command line arguments.

    Returns:
      A dictionary with perf config parameters.
    """
    # To make sure that we don't mutate the original args
    arguments = arguments[:]

    # Always set verbose logging for later debugging
    if '-v' not in arguments and '--verbose' not in arguments:
      arguments.append('--verbose')

    # Generate the command line for the perf trybots
    target_arch = 'ia32'
    if any(arg == '--chrome-root' or arg.startswith('--chrome-root=') for arg
           in arguments):
      raise ValueError(
          'Trybot does not suport --chrome-root option set directly '
          'through command line since it may contain references to your local '
          'directory')

    arguments.insert(0, 'src/tools/perf/run_benchmark')
    if bot_platform == 'android':
      arguments.insert(1, '--browser=android-chromium')
    elif any('x64' in bot for bot in self._builder_names[bot_platform]):
      arguments.insert(1, '--browser=release_x64')
      target_arch = 'x64'
    else:

      arguments.insert(1, '--browser=release')

    command = ' '.join(arguments)

    return {
        'command': command,
        'repeat_count': '1',
        'max_time_minutes': '120',
        'truncate_percent': '0',
        'target_arch': target_arch,
    }

  def _GetRepoAndBranchName(self, repo_path):
    """Gets the repository name and working branch name.

    Args:
      repo_path: Path to the repository.

    Returns:
      Repository name and branch name as tuple.

    Raises:
      TrybotError: This exception is raised for the following cases:
        1. Try job is for non-git repository or in invalid branch.
        2. Un-committed changes in the current branch.
        3. No local commits in the current branch.
    """
    # If command runs successfully, then the output will be repo root path.
    # and current branch name.
    output = RunGit(['rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
                    ('%s is not a git repository, must be in a git repository '
                     'to send changes to trybots' % os.getcwd()))

    repo_info = output.split()
    # Assuming the base directory name is same as repo project name set in
    # codereviews.settings file.
    repo_name = os.path.basename(repo_info[0]).strip()
    branch_name = repo_info[1].strip()

    if branch_name == 'HEAD':
      raise TrybotError('Not on a valid branch, looks like branch '
                        'is dettached. [branch:%s]' % branch_name)

    # Check if the tree is dirty: make sure the index is up to date and then
    # run diff-index
    RunGit(['update-index', '--refresh', '-q'], ignore_return_code=True)
    output = RunGit(['diff-index', 'HEAD'])
    if output:
      raise TrybotError(
          'Cannot send a try job with a dirty tree. Please commit '
          'your changes locally first in %s repository.' % repo_path)

    # Make sure the tree does have local commits.
    output = RunGit(['footers', 'HEAD'])
    if output:
      raise TrybotError('No local changes found in %s repository.' % repo_path)

    return (repo_name, branch_name)

  def _AttemptTryjob(self, repo_path, options, extra_args):
    """Attempts to run a tryjob from a repo directory.

    Args:
      repo_path: Path to the repository.
      options: Command line arguments to run benchmark.
      extra_args: Extra arugments to run benchmark.
    """
    repo_name, branch_name = self._GetRepoAndBranchName(repo_path)

    arguments = [options.benchmark_name] + extra_args

    rietveld_url = self._UploadPatchToRietveld(repo_name, options)
    print ('\nUploaded try job to rietveld.\nview progress here %s.'
           '\n\tRepo Name: %s\n\tPath: %s\n\tBranch: %s' % (
               rietveld_url, repo_name, repo_path, branch_name))

    for bot_platform in self._builder_names:
      if not self._builder_names[bot_platform]:
        logging.warning('No builder is found for %s', bot_platform)
        continue
      try:
        self._RunTryJob(bot_platform, arguments)
      except TrybotError, err:
        print err

  def _UploadPatchToRietveld(self, repo_name, options):
    """Uploads the patch to rietveld and returns rietveld URL."""
    output = RunGit(['cl', 'upload', '-f', '--bypass-hooks', '-m',
                     ('CL for %s perf tryjob to run %s benchmark '
                      'on %s platform(s)' % (
                          repo_name, options.benchmark_name, options.trybot))],
                    'Could not upload to rietveld for %s' % repo_name)

    match = re.search(r'https://codereview.chromium.org/[\d]+', output)
    if not match:
      raise TrybotError('Could not upload CL to rietveld for %s! Output %s' %
                        (repo_name, output))
    return match.group(0)

  def _RunTryJob(self, bot_platform, arguments):
    """Executes perf try job with benchmark test properties.

    Args:
      bot_platform: Name of the platform to be generated.
      arguments: Command line arguments.

    Raises:
      TrybotError: When trybot fails to upload CL or run git try.
    """
    config = self._GetPerfConfig(bot_platform, arguments)

    # Generate git try command for available bots.
    git_try_command = ['cl', 'try', '-m', 'tryserver.chromium.perf']

     # Add Perf Test config to git try --properties arg.
    git_try_command.extend(['-p', 'perf_try_config=%s' % json.dumps(config)])

    for bot in self._builder_names[bot_platform]:
      git_try_command.extend(['-b', bot])

    RunGit(git_try_command, 'Could not try CL for %s' % bot_platform)
    print 'Perf Try job sent to rietveld for %s platform.' % bot_platform

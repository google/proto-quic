# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import base64
import gzip
import io
import json
import logging
import os
import platform
import subprocess
import tempfile
import urllib
import urllib2


from core import benchmark_finders
from core import path_util

from telemetry import benchmark
from telemetry import decorators
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
# Mapping of repo to its root path and git remote URL.
# Values for 'src' key in the map are related to path to the repo in the
# DEPS file, These values are to used create the DEPS patch along with patch
# that is being tried.
REPO_INFO_MAP = {
    'src': {
        'src': 'src',
        'url': 'https://chromium.googlesource.com/chromium/src.git',
    },
    'v8': {
        'src': 'src/v8',
        'url': 'https://chromium.googlesource.com/v8/v8.git',
    },
    'skia': {
        'src': 'src/third_party/skia',
        'url': 'https://chromium.googlesource.com/skia.git',
    },
    'angle': {
        'src': 'src/third_party/angle',
        'url': 'https://chromium.googlesource.com/angle/angle.git',
    },
    'catapult': {
        'src': 'src/third_party/catapult',
        'url': ('https://chromium.googlesource.com/external/github.com/'
                'catapult-project/catapult.git')
    }
}

_MILO_MASTER_ENDPOINT = ('https://luci-milo.appspot.com/prpc/milo.Buildbot/'
                        'GetCompressedMasterJSON')

_MILO_RESPONSE_PREFIX = ')]}\'\n'


assert not set(DEFAULT_TRYBOTS) & set(EXCLUDED_BOTS), (
    'A trybot cannot present in both Default as well as Excluded bots lists.')


class TrybotError(Exception):

  def __str__(self):
    return '(ERROR) Perf Try Job: %s' % self.args[0]


def _ProcessMiloData(data):
  if not data.startswith(_MILO_RESPONSE_PREFIX):
    return None
  data = data[len(_MILO_RESPONSE_PREFIX):]

  try:
    response_data = json.loads(data)
  except Exception:
    return None

  try:
    decoded_data = base64.b64decode(response_data.get('data'))
  except Exception:
    return None

  try:
    with io.BytesIO(decoded_data) as compressed_file:
      with gzip.GzipFile(fileobj=compressed_file) as decompressed_file:
        data_json = decompressed_file.read()
  except Exception:
    return None

  return json.loads(data_json)


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
    raise TrybotError('%s. \n%s \n%s' % (msg_on_error, err, output))

  return output.strip()


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
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        values = {'name': 'tryserver.chromium.perf'}
        data = urllib.urlencode(values)
        req = urllib2.Request(_MILO_MASTER_ENDPOINT, None, headers)
        f = urllib2.urlopen(req, json.dumps(values), timeout=10)
      # In case of any kind of exception, allow tryjobs to use default trybots.
      # Possible exception are ssl.SSLError, urllib2.URLError,
      # socket.timeout, socket.error.
      except Exception:  # pylint: disable=broad-except
        # Incase of any exception return default trybots.
        print ('WARNING: Unable to reach builbot to retrieve trybot '
               'information, tryjob will use default trybots.')
        cls._builders = DEFAULT_TRYBOTS
      else:
        data = _ProcessMiloData(f.read())
        builders = data.get('builders', {}).keys()
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
    all_benchmarks = benchmark_finders.GetAllPerfBenchmarks()
    all_benchmarks.extend(benchmark_finders.GetAllContribBenchmarks())
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
    parser.add_argument(
        '--repo_path', type=str, default=CHROMIUM_SRC_PATH,
        help=("""specify the repo path where the patch is created.'
This argument should only be used if the changes are made outside chromium repo.
E.g.,
1) Assume you are running run_benchmarks command from $HOME/cr/src/ direcory:'
  a) If your changes are in $HOME/cr/src/v8, then --repo_path=v8 or
     --repo-path=$HOME/cr/src/v8
  b) If your changes are in $HOME/cr/src/third_party/catapult, then
     --repo_path=third_party/catapult or
     --repo_path = $HOME/cr/src/third_party/catapult'
  c) If your changes are not relative to src/ e.g. you created changes in some
     other direcotry say $HOME/mydir/v8/v8/, then the
     --repo_path=$HOME/mydir/v8/v8
2) Assume you are running run_benchmarks command not relatvie to src i.e.,
   you are running from $HOME/mydir/ direcory:'
   a) If your changes are in $HOME/cr/src/v8, then --repo-path=$HOME/cr/src/v8
   b) If your changes are in $HOME/cr/src/third_party/catapult, then
      --repo_path=$HOME/cr/src/third_party/catapult'
  c) If your changes are in $HOME/mydir/v8/v8/, then the
     --repo_path=$HOME/mydir/v8/v8 or --repo_path=v8/v8"""),
        metavar='<repo path>')
    parser.add_argument(
        '--deps_revision', type=str, default=None,
        help=('specify DEPS revision to modify DEPS entry in Chromium to a '
              'certain pushed revision.\n'
              'This revision overrides value in DEPS on TOT Chromium for the '
              'repo specified in --repo_path.\nIt is applied for both with and '
              'wihout patch.'),
        metavar='<deps revision>')

  def Run(self, options, extra_args=None):
    """Sends a tryjob to a perf trybot.

    This creates a branch, telemetry-tryjob, switches to that branch, edits
    the bisect config, commits it, uploads the CL to rietveld, and runs a
    tryjob on the given bot.
    """
    if extra_args is None:
      extra_args = []
    self._InitializeBuilderNames(options.trybot)

    return self._AttemptTryjob(options, extra_args)

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
          'Cannot send a try job with a dirty tree.\nPlease commit locally and '
          'upload your changes to rietveld in %s repository.' % repo_path)

    return (repo_name, branch_name)

  def _GetBaseGitHashForRepo(self, branch_name, git_url):
    """Gets the base revision for the repo on which local changes are made.

    Finds the upstream of the current branch that it is set to and gets
    the HEAD revision from upstream. This also checks if the remote URL on
    the upstream is supported by Perf Try job.

    Args:
      branch_name: Current working branch name.
      git_url: Remote URL of the repo.

    Returns:
      Git hash of the HEAD revision from the upstream branch.

    Raises:
      TrybotError: This exception is raised when a GIT command fails or if the
      remote URL of the repo found is not supported.
    """
    # Check if there is any upstream branch associated with current working
    # branch, Once the upstream branch is found i.e., then validates the
    # remote URL and then returns the HEAD revision from the remote branch.
    while not self._IsRepoSupported(branch_name, git_url):
      branch_name = RunGit(
          ['rev-parse', '--abbrev-ref', '%s@{upstream}' % branch_name],
          'Failed to get upstream branch name.')

    return RunGit(
        ['rev-parse', '%s@{upstream}' % branch_name],
        'Failed to get base revision hash on upstream.')

  def _IsRepoSupported(self, current_branch, repo_git_url):
    cur_remote = RunGit(
        ['config', 'branch.%s.remote'% current_branch],
        'Failed to get branch.%s.remote from git config' % current_branch)
    cur_remote = cur_remote.strip()
    if cur_remote == '.':
      return False
    cur_remote_url = RunGit(
        ['config', 'remote.%s.url' % cur_remote],
        'Failed to get remote.%s.url from git config' % cur_remote)
    if cur_remote_url.lower() == repo_git_url:
      return True
    raise TrybotError('URL %s on remote %s is not recognized on branch.'% (
        cur_remote_url, cur_remote))

  def _GetChangeList(self):
    """Gets the codereview URL for the current changes."""
    temp_file = None
    json_output = None
    try:
      fd, temp_file = tempfile.mkstemp(suffix='.json', prefix='perf_try_cl')
      os.close(fd)
      RunGit(['cl', 'issue', '--json', temp_file],
              'Failed to run "git cl issue" command.')
      with open(temp_file, 'r') as f:
        json_output = json.load(f)
    finally:
      try:
        if temp_file:
          os.remove(temp_file)
      except OSError:
        pass

    # Make sure the local commits are uploaded to rietveld.
    if not json_output.get('issue'):
      raise TrybotError(
          'PLEASE NOTE: The workflow for Perf Try jobs is changed. '
          'In order to run the perf try job, you must first upload your '
          'changes to rietveld.')
    return json_output.get('issue_url')

  def _AttemptTryjob(self, options, extra_args):
    """Attempts to run a tryjob from a repo directory.

    Args:
      options: Command line arguments to run benchmark.
      extra_args: Extra arugments to run benchmark.

    Returns:
     If successful returns 0, otherwise 1.
    """
    original_workdir = os.getcwd()
    repo_path = os.path.abspath(options.repo_path)
    try:
      # Check the existence of repo path.
      if not os.path.exists(repo_path):
        raise TrybotError('Repository path "%s" does not exist, please check '
                          'the value of <repo_path> argument.' % repo_path)
      # Change to the repo directory.
      os.chdir(repo_path)
      repo_name, branch_name = self._GetRepoAndBranchName(repo_path)

      repo_info = REPO_INFO_MAP.get(repo_name, None)
      if not repo_info:
        raise TrybotError('Unsupported repository %s' % repo_name)

      deps_override = None
      if repo_name != 'src':
        if not options.deps_revision:
          options.deps_revision = self._GetBaseGitHashForRepo(
              branch_name, repo_info.get('url'))
        deps_override = {repo_info.get('src'): options.deps_revision}

      rietveld_url = self._GetChangeList()
      print ('\nRunning try job....\nview progress here %s.'
             '\n\tRepo Name: %s\n\tPath: %s\n\tBranch: %s' % (
                 rietveld_url, repo_name, repo_path, branch_name))

      for bot_platform in self._builder_names:
        if not self._builder_names[bot_platform]:
          logging.warning('No builder is found for %s', bot_platform)
          continue
        try:
          arguments = [options.benchmark_name] + extra_args
          self._RunTryJob(bot_platform, arguments, deps_override)
        # Even if git cl try throws TrybotError exception for any platform,
        # keep sending try jobs to other platforms.
        except TrybotError, err:
          print err
    except TrybotError, error:
      print error
      return 1
    finally:
      # Restore to original working directory.
      os.chdir(original_workdir)
    return 0

  def _RunTryJob(self, bot_platform, arguments, deps_override):
    """Executes perf try job with benchmark test properties.

    Args:
      bot_platform: Name of the platform to be generated.
      arguments: Command line arguments.
      deps_override: DEPS revision if needs to be overridden.

    Raises:
      TrybotError: When trybot fails to upload CL or run git try.
    """
    config = self._GetPerfConfig(bot_platform, arguments)

    # Generate git try command for available bots.
    git_try_command = ['cl', 'try', '-m', 'tryserver.chromium.perf']

     # Add Perf Test config to git try --properties arg.
    git_try_command.extend(['-p', 'perf_try_config=%s' % json.dumps(config)])

    error_msg_on_fail = 'Could not try CL for %s' % bot_platform
    # Add deps overrides to git try --properties arg.
    if deps_override:
      git_try_command.extend([
          '-p', 'deps_revision_overrides=%s' % json.dumps(deps_override)])
      error_msg_on_fail += ' with DEPS override (%s)' % deps_override
    for bot in self._builder_names[bot_platform]:
      git_try_command.extend(['-b', bot])

    RunGit(git_try_command, error_msg_on_fail)
    print 'Perf Try job sent to rietveld for %s platform.' % bot_platform

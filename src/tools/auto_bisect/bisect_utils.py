# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility functions used by the bisect tool.

This includes functions related to checking out the depot and outputting
annotations for the Buildbot waterfall.
"""

import errno
import imp
import os
import stat
import subprocess
import sys

DEFAULT_GCLIENT_CUSTOM_DEPS = {
    'src/data/page_cycler': 'https://chrome-internal.googlesource.com/'
                            'chrome/data/page_cycler/.git',
    'src/data/dom_perf': 'https://chrome-internal.googlesource.com/'
                         'chrome/data/dom_perf/.git',
    'src/data/mach_ports': 'https://chrome-internal.googlesource.com/'
                           'chrome/data/mach_ports/.git',
    'src/tools/perf/data': 'https://chrome-internal.googlesource.com/'
                           'chrome/tools/perf/data/.git',
    'src/third_party/adobe/flash/binaries/ppapi/linux':
        'https://chrome-internal.googlesource.com/'
        'chrome/deps/adobe/flash/binaries/ppapi/linux/.git',
    'src/third_party/adobe/flash/binaries/ppapi/linux_x64':
        'https://chrome-internal.googlesource.com/'
        'chrome/deps/adobe/flash/binaries/ppapi/linux_x64/.git',
    'src/third_party/adobe/flash/binaries/ppapi/mac':
        'https://chrome-internal.googlesource.com/'
        'chrome/deps/adobe/flash/binaries/ppapi/mac/.git',
    'src/third_party/adobe/flash/binaries/ppapi/mac_64':
        'https://chrome-internal.googlesource.com/'
        'chrome/deps/adobe/flash/binaries/ppapi/mac_64/.git',
    'src/third_party/adobe/flash/binaries/ppapi/win':
        'https://chrome-internal.googlesource.com/'
        'chrome/deps/adobe/flash/binaries/ppapi/win/.git',
    'src/third_party/adobe/flash/binaries/ppapi/win_x64':
        'https://chrome-internal.googlesource.com/'
        'chrome/deps/adobe/flash/binaries/ppapi/win_x64/.git',
    'src/third_party/WebKit/LayoutTests': None,
    'src/tools/valgrind': None,
}

GCLIENT_SPEC_DATA = [
    {
        'name': 'src',
        'url': 'https://chromium.googlesource.com/chromium/src.git',
        'deps_file': '.DEPS.git',
        'managed': True,
        'custom_deps': {},
        'safesync_url': '',
    },
]
GCLIENT_SPEC_ANDROID = "\ntarget_os = ['android']"
GCLIENT_CUSTOM_DEPS_V8 = {
    'src/v8_bleeding_edge': 'https://chromium.googlesource.com/v8/v8.git'
}
FILE_DEPS_GIT = '.DEPS.git'
FILE_DEPS = 'DEPS'

# Bisect working directory.
BISECT_DIR = 'bisect'

# The percentage at which confidence is considered high.
HIGH_CONFIDENCE = 95

# Below is the map of "depot" names to information about each depot. Each depot
# is a repository, and in the process of bisecting, revision ranges in these
# repositories may also be bisected.
#
# Each depot information dictionary may contain:
#   src: Path to the working directory.
#   recurse: True if this repository will get bisected.
#   svn: URL of SVN repository. Needed for git workflow to resolve hashes to
#       SVN revisions.
#   from: Parent depot that must be bisected before this is bisected.
#   deps_var: Key name in vars variable in DEPS file that has revision
#       information.
DEPOT_DEPS_NAME = {
    'chromium': {
        'src': 'src',
        'recurse': True,
        'from': ['android-chrome'],
        'viewvc': 'https://chromium.googlesource.com/chromium/src/+/',
        'deps_var': 'chromium_rev'
    },
    'webkit': {
        'src': 'src/third_party/WebKit',
        'recurse': True,
        'from': ['chromium'],
        'viewvc': 'https://chromium.googlesource.com/chromium/blink/+/',
        'deps_var': 'webkit_revision'
    },
    'angle': {
        'src': 'src/third_party/angle',
        'src_old': 'src/third_party/angle_dx11',
        'recurse': True,
        'from': ['chromium'],
        'platform': 'nt',
        'viewvc': 'https://chromium.googlesource.com/angle/angle/+/',
        'deps_var': 'angle_revision'
    },
    'v8': {
        'src': 'src/v8',
        'recurse': True,
        'from': ['chromium'],
        'custom_deps': GCLIENT_CUSTOM_DEPS_V8,
        'viewvc': 'https://chromium.googlesource.com/v8/v8.git/+/',
        'deps_var': 'v8_revision'
    },
    'v8_bleeding_edge': {
        'src': 'src/v8_bleeding_edge',
        'recurse': True,
        'svn': 'https://v8.googlecode.com/svn/branches/bleeding_edge',
        'from': ['v8'],
        'viewvc': 'https://chromium.googlesource.com/v8/v8.git/+/',
        'deps_var': 'v8_revision'
    },
    'skia': {
        'src': 'src/third_party/skia',
        'recurse': True,
        'from': ['chromium'],
        'viewvc': 'https://chromium.googlesource.com/skia/+/',
        'deps_var': 'skia_revision'
    }
}

DEPOT_NAMES = DEPOT_DEPS_NAME.keys()

# The possible values of the --bisect_mode flag, which determines what to
# use when classifying a revision as "good" or "bad".
BISECT_MODE_MEAN = 'mean'
BISECT_MODE_STD_DEV = 'std_dev'
BISECT_MODE_RETURN_CODE = 'return_code'


def AddAdditionalDepotInfo(depot_info):
  """Adds additional depot info to the global depot variables."""
  global DEPOT_DEPS_NAME
  global DEPOT_NAMES
  DEPOT_DEPS_NAME = dict(DEPOT_DEPS_NAME.items() + depot_info.items())
  DEPOT_NAMES = DEPOT_DEPS_NAME.keys()


def OutputAnnotationStepStart(name):
  """Outputs annotation to signal the start of a step to a try bot.

  Args:
    name: The name of the step.
  """
  print
  print '@@@SEED_STEP %s@@@' % name
  print '@@@STEP_CURSOR %s@@@' % name
  print '@@@STEP_STARTED@@@'
  print
  sys.stdout.flush()


def OutputAnnotationStepClosed():
  """Outputs annotation to signal the closing of a step to a try bot."""
  print
  print '@@@STEP_CLOSED@@@'
  print
  sys.stdout.flush()


def OutputAnnotationStepText(text):
  """Outputs appropriate annotation to print text.

  Args:
    name: The text to print.
  """
  print
  print '@@@STEP_TEXT@%s@@@' % text
  print
  sys.stdout.flush()


def OutputAnnotationStepWarning():
  """Outputs appropriate annotation to signal a warning."""
  print
  print '@@@STEP_WARNINGS@@@'
  print


def OutputAnnotationStepFailure():
  """Outputs appropriate annotation to signal a warning."""
  print
  print '@@@STEP_FAILURE@@@'
  print


def OutputAnnotationStepLink(label, url):
  """Outputs appropriate annotation to print a link.

  Args:
    label: The name to print.
    url: The URL to print.
  """
  print
  print '@@@STEP_LINK@%s@%s@@@' % (label, url)
  print
  sys.stdout.flush()


def LoadExtraSrc(path_to_file):
  """Attempts to load an extra source file, and overrides global values.

  If the extra source file is loaded successfully, then it will use the new
  module to override some global values, such as gclient spec data.

  Args:
    path_to_file: File path.

  Returns:
    The loaded module object, or None if none was imported.
  """
  try:
    global GCLIENT_SPEC_DATA
    global GCLIENT_SPEC_ANDROID
    extra_src = imp.load_source('data', path_to_file)
    GCLIENT_SPEC_DATA = extra_src.GetGClientSpec()
    GCLIENT_SPEC_ANDROID = extra_src.GetGClientSpecExtraParams()
    return extra_src
  except ImportError:
    return None


def IsTelemetryCommand(command):
  """Attempts to discern whether or not a given command is running telemetry."""
  return 'tools/perf/run_' in command or 'tools\\perf\\run_' in command


def _CreateAndChangeToSourceDirectory(working_directory):
  """Creates a directory 'bisect' as a subdirectory of |working_directory|.

  If successful, the current working directory will be changed to the new
  'bisect' directory.

  Args:
    working_directory: The directory to create the new 'bisect' directory in.

  Returns:
    True if the directory was successfully created (or already existed).
  """
  cwd = os.getcwd()
  os.chdir(working_directory)
  try:
    os.mkdir(BISECT_DIR)
  except OSError, e:
    if e.errno != errno.EEXIST:  # EEXIST indicates that it already exists.
      os.chdir(cwd)
      return False
  os.chdir(BISECT_DIR)
  return True


def _SubprocessCall(cmd, cwd=None):
  """Runs a command in a subprocess.

  Args:
    cmd: The command to run.
    cwd: Working directory to run from.

  Returns:
    The return code of the call.
  """
  if os.name == 'nt':
    # "HOME" isn't normally defined on windows, but is needed
    # for git to find the user's .netrc file.
    if not os.getenv('HOME'):
      os.environ['HOME'] = os.environ['USERPROFILE']
  shell = os.name == 'nt'
  return subprocess.call(cmd, shell=shell, cwd=cwd)


def RunGClient(params, cwd=None):
  """Runs gclient with the specified parameters.

  Args:
    params: A list of parameters to pass to gclient.
    cwd: Working directory to run from.

  Returns:
    The return code of the call.
  """
  cmd = ['gclient'] + params
  return _SubprocessCall(cmd, cwd=cwd)


def RunGClientAndCreateConfig(opts, custom_deps=None, cwd=None):
  """Runs gclient and creates a config containing both src and src-internal.

  Args:
    opts: The options parsed from the command line through parse_args().
    custom_deps: A dictionary of additional dependencies to add to .gclient.
    cwd: Working directory to run from.

  Returns:
    The return code of the call.
  """
  spec = GCLIENT_SPEC_DATA

  if custom_deps:
    for k, v in custom_deps.iteritems():
      spec[0]['custom_deps'][k] = v

  # Cannot have newlines in string on windows
  spec = 'solutions =' + str(spec)
  spec = ''.join([l for l in spec.splitlines()])

  if 'android' in opts.target_platform:
    spec += GCLIENT_SPEC_ANDROID

  return_code = RunGClient(
      ['config', '--spec=%s' % spec], cwd=cwd)
  return return_code


def OnAccessError(func, path, _):
  """Error handler for shutil.rmtree.

  Source: http://goo.gl/DEYNCT

  If the error is due to an access error (read only file), it attempts to add
  write permissions, then retries.

  If the error is for another reason it re-raises the error.

  Args:
    func: The function that raised the error.
    path: The path name passed to func.
    _: Exception information from sys.exc_info(). Not used.
  """
  if not os.access(path, os.W_OK):
    os.chmod(path, stat.S_IWUSR)
    func(path)
  else:
    raise


def _CleanupPreviousGitRuns(cwd=os.getcwd()):
  """Cleans up any leftover index.lock files after running git."""
  # If a previous run of git crashed, or bot was reset, etc., then we might
  # end up with leftover index.lock files.
  for path, _, files in os.walk(cwd):
    for cur_file in files:
      if cur_file.endswith('index.lock'):
        path_to_file = os.path.join(path, cur_file)
        os.remove(path_to_file)


def RunGClientAndSync(revisions=None, cwd=None):
  """Runs gclient and does a normal sync.

  Args:
    revisions: List of revisions that need to be synced.
        E.g., "src@2ae43f...", "src/third_party/webkit@asr1234" etc.
    cwd: Working directory to run from.

  Returns:
    The return code of the call.
  """
  params = ['sync', '--verbose', '--nohooks', '--force',
            '--delete_unversioned_trees']
  if revisions is not None:
    for revision in revisions:
      if revision is not None:
        params.extend(['--revision', revision])
  return RunGClient(params, cwd=cwd)


def SetupGitDepot(opts, custom_deps):
  """Sets up the depot for the bisection.

  The depot will be located in a subdirectory called 'bisect'.

  Args:
    opts: The options parsed from the command line through parse_args().
    custom_deps: A dictionary of additional dependencies to add to .gclient.

  Returns:
    True if gclient successfully created the config file and did a sync, False
    otherwise.
  """
  name = 'Setting up Bisection Depot'
  try:
    if opts.output_buildbot_annotations:
      OutputAnnotationStepStart(name)

    if RunGClientAndCreateConfig(opts, custom_deps):
      return False

    _CleanupPreviousGitRuns()
    RunGClient(['revert'])
    return not RunGClientAndSync()
  finally:
    if opts.output_buildbot_annotations:
      OutputAnnotationStepClosed()


def CheckIfBisectDepotExists(opts):
  """Checks if the bisect directory already exists.

  Args:
    opts: The options parsed from the command line through parse_args().

  Returns:
    Returns True if it exists.
  """
  path_to_dir = os.path.join(opts.working_directory, BISECT_DIR, 'src')
  return os.path.exists(path_to_dir)


def CheckRunGit(command, cwd=None):
  """Run a git subcommand, returning its output and return code. Asserts if
  the return code of the call is non-zero.

  Args:
    command: A list containing the args to git.

  Returns:
    A tuple of the output and return code.
  """
  output, return_code = RunGit(command, cwd=cwd)

  assert not return_code, 'An error occurred while running'\
                          ' "git %s"' % ' '.join(command)
  return output


def RunGit(command, cwd=None):
  """Run a git subcommand, returning its output and return code.

  Args:
    command: A list containing the args to git.
    cwd: A directory to change to while running the git command (optional).

  Returns:
    A tuple of the output and return code.
  """
  command = ['git'] + command
  return RunProcessAndRetrieveOutput(command, cwd=cwd)


def CreateBisectDirectoryAndSetupDepot(opts, custom_deps):
  """Sets up a subdirectory 'bisect' and then retrieves a copy of the depot
  there using gclient.

  Args:
    opts: The options parsed from the command line through parse_args().
    custom_deps: A dictionary of additional dependencies to add to .gclient.
  """
  if CheckIfBisectDepotExists(opts):
    path_to_dir = os.path.join(os.path.abspath(opts.working_directory),
                               BISECT_DIR, 'src')
    output, _ = RunGit(['rev-parse', '--is-inside-work-tree'], cwd=path_to_dir)
    if output.strip() == 'true':
      # Before checking out master, cleanup up any leftover index.lock files.
      _CleanupPreviousGitRuns(path_to_dir)
      # Checks out the master branch, throws an exception if git command fails.
      CheckRunGit(['checkout', '-f', 'master'], cwd=path_to_dir)
  if not _CreateAndChangeToSourceDirectory(opts.working_directory):
    raise RuntimeError('Could not create bisect directory.')

  if not SetupGitDepot(opts, custom_deps):
    raise RuntimeError('Failed to grab source.')


def RunProcess(command, cwd=None, shell=False):
  """Runs an arbitrary command.

  If output from the call is needed, use RunProcessAndRetrieveOutput instead.

  Args:
    command: A list containing the command and args to execute.

  Returns:
    The return code of the call.
  """
  # On Windows, use shell=True to get PATH interpretation.
  shell = shell or IsWindowsHost()
  return subprocess.call(command, cwd=cwd, shell=shell)


def RunProcessAndRetrieveOutput(command, cwd=None):
  """Runs an arbitrary command, returning its output and return code.

  Since output is collected via communicate(), there will be no output until
  the call terminates. If you need output while the program runs (ie. so
  that the buildbot doesn't terminate the script), consider RunProcess().

  Args:
    command: A list containing the command and args to execute.
    cwd: A directory to change to while running the command. The command can be
        relative to this directory. If this is None, the command will be run in
        the current directory.

  Returns:
    A tuple of the output and return code.
  """
  if cwd:
    original_cwd = os.getcwd()
    os.chdir(cwd)

  # On Windows, use shell=True to get PATH interpretation.
  shell = IsWindowsHost()
  proc = subprocess.Popen(
      command, shell=shell, stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT)
  output, _ = proc.communicate()

  if cwd:
    os.chdir(original_cwd)

  return (output, proc.returncode)


def IsStringInt(string_to_check):
  """Checks whether or not the given string can be converted to an int."""
  try:
    int(string_to_check)
    return True
  except ValueError:
    return False


def IsStringFloat(string_to_check):
  """Checks whether or not the given string can be converted to a float."""
  try:
    float(string_to_check)
    return True
  except ValueError:
    return False


def IsWindowsHost():
  return sys.platform == 'cygwin' or sys.platform.startswith('win')


def Is64BitWindows():
  """Checks whether or not Windows is a 64-bit version."""
  platform = os.environ.get('PROCESSOR_ARCHITEW6432')
  if not platform:
    # Must not be running in WoW64, so PROCESSOR_ARCHITECTURE is correct.
    platform = os.environ.get('PROCESSOR_ARCHITECTURE')
  return platform and platform in ['AMD64', 'I64']


def IsLinuxHost():
  return sys.platform.startswith('linux')


def IsMacHost():
  return sys.platform.startswith('darwin')

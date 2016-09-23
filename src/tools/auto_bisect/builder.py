# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Classes and functions for building Chrome.

This includes functions for running commands to build, as well as
specific rules about which targets to build.
"""

import os
import subprocess
import sys

import bisect_utils

ORIGINAL_ENV = {}


class Builder(object):
  """Subclasses of the Builder class are used by the bisect script to build
  relevant targets.
  """
  def __init__(self, opts):
    """Performs setup for building with target build system.

    Args:
      opts: Options parsed from command line.

    Raises:
      RuntimeError: Some condition necessary for building was not met.
    """
    if bisect_utils.IsWindowsHost():
      if not opts.build_preference:
        opts.build_preference = 'msvs'

      if opts.build_preference == 'msvs':
        if not os.getenv('VS100COMNTOOLS'):
          raise RuntimeError(
              'Path to visual studio could not be determined.')
      else:
        # Need to re-escape goma dir, see crbug.com/394990.
        if opts.goma_dir:
          opts.goma_dir = opts.goma_dir.encode('string_escape')
        SetBuildSystemDefault(opts.build_preference, opts.use_goma,
                              opts.goma_dir, opts.target_arch)
    else:
      if not opts.build_preference:
        if 'ninja' in os.getenv('GYP_GENERATORS', default=''):
          opts.build_preference = 'ninja'
        else:
          opts.build_preference = 'make'

      SetBuildSystemDefault(opts.build_preference, opts.use_goma, opts.goma_dir)

    if not SetupPlatformBuildEnvironment(opts):
      raise RuntimeError('Failed to set platform environment.')

  @staticmethod
  def FromOpts(opts):
    """Constructs and returns a Builder object.

    Args:
      opts: Options parsed from the command-line.
    """
    builder = None
    if opts.target_platform == 'android':
      builder = AndroidBuilder(opts)
    elif opts.target_platform == 'android-chrome':
      builder = AndroidChromeBuilder(opts)
    else:
      builder = DesktopBuilder(opts)
    return builder

  def Build(self, depot, opts):
    """Runs a command to build Chrome."""
    raise NotImplementedError()


def GetBuildOutputDirectory(opts, src_dir=None):
  """Returns the path to the build directory, relative to the checkout root.

  Assumes that the current working directory is the checkout root.

  Args:
    opts: Command-line options.
    src_dir: Path to chromium/src directory.

  Returns:
    A path to the directory to use as build output directory.

  Raises:
    NotImplementedError: The platform according to sys.platform is unexpected.
  """
  src_dir = src_dir or 'src'
  if opts.build_preference == 'ninja' or bisect_utils.IsLinuxHost():
    return os.path.join(src_dir, 'out')
  if bisect_utils.IsMacHost():
    return os.path.join(src_dir, 'xcodebuild')
  if bisect_utils.IsWindowsHost():
    return os.path.join(src_dir, 'build')
  raise NotImplementedError('Unexpected platform %s' % sys.platform)


class DesktopBuilder(Builder):
  """DesktopBuilder is used to build Chromium on Linux, Mac, or Windows."""

  def __init__(self, opts):
    super(DesktopBuilder, self).__init__(opts)

  def Build(self, depot, opts):
    """Builds chromium_builder_perf target using options passed into the script.

    Args:
      depot: Name of current depot being bisected.
      opts: The options parsed from the command line.

    Returns:
      True if build was successful.
    """
    targets = ['chromium_builder_perf']

    threads = None
    if opts.use_goma:
      threads = opts.goma_threads

    build_success = False
    if opts.build_preference == 'make':
      build_success = BuildWithMake(threads, targets, opts.target_build_type)
    elif opts.build_preference == 'ninja':
      build_success = BuildWithNinja(threads, targets, opts.target_build_type)
    elif opts.build_preference == 'msvs':
      assert bisect_utils.IsWindowsHost(), 'msvs is only supported on Windows.'
      build_success = BuildWithVisualStudio(targets, opts.target_build_type)
    else:
      assert False, 'No build system defined.'
    return build_success


class AndroidBuilder(Builder):
  """AndroidBuilder is used to build on android."""

  def __init__(self, opts):
    super(AndroidBuilder, self).__init__(opts)

  # TODO(qyearsley): Make this a class method and verify that it works with
  # a unit test.
  # pylint: disable=R0201
  def _GetTargets(self):
    """Returns a list of build targets."""
    return [
        'chrome_public_apk',
        'cc_perftests_apk',
        'android_tools'
    ]

  def Build(self, depot, opts):
    """Builds the android content shell and other necessary tools.

    Args:
        depot: Current depot being bisected.
        opts: The options parsed from the command line.

    Returns:
        True if build was successful.
    """
    threads = None
    if opts.use_goma:
      threads = opts.goma_threads

    build_success = False
    if opts.build_preference == 'ninja':
      build_success = BuildWithNinja(
          threads, self._GetTargets(), opts.target_build_type)
    else:
      assert False, 'No build system defined.'

    return build_success


class AndroidChromeBuilder(AndroidBuilder):
  """AndroidChromeBuilder is used to build "android-chrome".

  This is slightly different from AndroidBuilder.
  """

  def __init__(self, opts):
    super(AndroidChromeBuilder, self).__init__(opts)

  # TODO(qyearsley): Make this a class method and verify that it works with
  # a unit test.
  # pylint: disable=R0201
  def _GetTargets(self):
    """Returns a list of build targets."""
    return AndroidBuilder._GetTargets(self) + ['chrome_apk']


def SetBuildSystemDefault(build_system, use_goma, goma_dir, target_arch='ia32'):
  """Sets up any environment variables needed to build with the specified build
  system.

  Args:
    build_system: A string specifying build system. Currently only 'ninja' or
        'make' are supported.
    use_goma: Determines whether to GOMA for compile.
    goma_dir: GOMA directory path.
    target_arch: The target build architecture, ia32 or x64. Default is ia32.
  """
  if build_system == 'ninja':
    gyp_var = os.getenv('GYP_GENERATORS', default='')

    if not gyp_var or not 'ninja' in gyp_var:
      if gyp_var:
        os.environ['GYP_GENERATORS'] = gyp_var + ',ninja'
      else:
        os.environ['GYP_GENERATORS'] = 'ninja'

      if bisect_utils.IsWindowsHost():
        os.environ['GYP_DEFINES'] = 'component=shared_library '\
            'incremental_chrome_dll=1 disable_nacl=1 fastbuild=1 '\
            'chromium_win_pch=0'

  elif build_system == 'make':
    os.environ['GYP_GENERATORS'] = 'make'
  else:
    raise RuntimeError('%s build not supported.' % build_system)

  if use_goma:
    os.environ['GYP_DEFINES'] = '%s %s' % (os.getenv('GYP_DEFINES', default=''),
                                           'use_goma=1')
    if goma_dir:
      os.environ['GYP_DEFINES'] += ' gomadir=%s' % goma_dir

  # Produce 64 bit chromium binaries when target architecure is set to x64.
  if target_arch == 'x64':
    os.environ['GYP_DEFINES'] += ' target_arch=%s' % target_arch

def SetupPlatformBuildEnvironment(opts):
  """Performs any platform-specific setup.

  Args:
    opts: The options parsed from the command line through parse_args().

  Returns:
    True if successful.
  """
  if 'android' in opts.target_platform:
    CopyAndSaveOriginalEnvironmentVars()
    return SetupAndroidBuildEnvironment(opts)
  return True


def BuildWithMake(threads, targets, build_type='Release'):
  """Runs a make command with the given targets.

  Args:
    threads: The number of threads to use. None means unspecified/unlimited.
    targets: List of make targets.
    build_type: Release or Debug.

  Returns:
    True if the command had a 0 exit code, False otherwise.
  """
  cmd = ['make', 'BUILDTYPE=%s' % build_type]
  if threads:
    cmd.append('-j%d' % threads)
  cmd += targets
  return_code = bisect_utils.RunProcess(cmd)
  return not return_code


def BuildWithNinja(threads, targets, build_type='Release'):
  """Runs a ninja command with the given targets."""
  cmd = ['ninja', '-C', os.path.join('out', build_type)]
  if threads:
    cmd.append('-j%d' % threads)
  cmd += targets
  return_code = bisect_utils.RunProcess(cmd)
  return not return_code


def BuildWithVisualStudio(targets, build_type='Release'):
  """Runs a command to build the given targets with Visual Studio."""
  path_to_devenv = os.path.abspath(
      os.path.join(os.environ['VS100COMNTOOLS'], '..', 'IDE', 'devenv.com'))
  path_to_sln = os.path.join(os.getcwd(), 'chrome', 'chrome.sln')
  cmd = [path_to_devenv, '/build', build_type, path_to_sln]
  for t in targets:
    cmd.extend(['/Project', t])
  return_code = bisect_utils.RunProcess(cmd)
  return not return_code


def CopyAndSaveOriginalEnvironmentVars():
  """Makes a copy of the current environment variables.

  Before making a copy of the environment variables and setting a global
  variable, this function unsets a certain set of environment variables.
  """
  # TODO: Waiting on crbug.com/255689, will remove this after.
  vars_to_remove = [
      'CHROME_SRC',
      'CHROMIUM_GYP_FILE',
      'GYP_DEFINES',
      'GYP_GENERATORS',
      'GYP_GENERATOR_FLAGS',
      'OBJCOPY',
  ]
  for key in os.environ:
    if 'ANDROID' in key:
      vars_to_remove.append(key)
  for key in vars_to_remove:
    if os.environ.has_key(key):
      del os.environ[key]

  global ORIGINAL_ENV
  ORIGINAL_ENV = os.environ.copy()


def SetupAndroidBuildEnvironment(opts, path_to_src=None):
  """Sets up the android build environment.

  Args:
    opts: The options parsed from the command line through parse_args().
    path_to_src: Path to the src checkout.

  Returns:
    True if successful.
  """
  # Revert the environment variables back to default before setting them up
  # with envsetup.sh.
  env_vars = os.environ.copy()
  for k, _ in env_vars.iteritems():
    del os.environ[k]
  for k, v in ORIGINAL_ENV.iteritems():
    os.environ[k] = v

  envsetup_path = os.path.join('build', 'android', 'envsetup.sh')
  proc = subprocess.Popen(['bash', '-c', 'source %s && env' % envsetup_path],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          cwd=path_to_src)
  out, _ = proc.communicate()

  for line in out.splitlines():
    k, _, v = line.partition('=')
    os.environ[k] = v

  # envsetup.sh no longer sets OS=android in GYP_DEFINES environment variable.
  # (See http://crrev.com/170273005). So, we set this variable explicitly here
  # in order to build Chrome on Android.
  if 'GYP_DEFINES' not in os.environ:
    os.environ['GYP_DEFINES'] = 'OS=android'
  else:
    os.environ['GYP_DEFINES'] += ' OS=android'

  if opts.use_goma:
    os.environ['GYP_DEFINES'] += ' use_goma=1'
  return not proc.returncode

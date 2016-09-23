# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The android specific platform implementation module."""

import os
import subprocess

import cr

# This is the set of environment variables that are not automatically
# copied back from the envsetup shell
_IGNORE_ENV = [
    'SHLVL',  # Because it's nothing to do with envsetup
    'GYP_GENERATOR_FLAGS',  # because we set them in they gyp handler
    'GYP_GENERATORS',  # because we set them in they gyp handler
    'PATH',  # Because it gets a special merge handler
    'GYP_DEFINES',  # Because it gets a special merge handler
]


class AndroidPlatform(cr.Platform):
  """The implementation of Platform for the android target."""

  ACTIVE = cr.Config.From(
      CR_ENVSETUP=os.path.join('{CR_SRC}', 'build', 'android', 'envsetup.sh'),
      CR_ADB=os.path.join('{CR_SRC}', 'third_party', 'android_tools', 'sdk',
          'platform-tools', 'adb'),
      CR_TARGET_SUFFIX='_apk',
      CR_BINARY=os.path.join('{CR_BUILD_DIR}', 'apks', '{CR_TARGET_NAME}.apk'),
      CR_ACTION='android.intent.action.VIEW',
      CR_PACKAGE='com.google.android.apps.{CR_TARGET}',
      CR_PROCESS='{CR_PACKAGE}',
      CR_ACTIVITY='.Main',
      CR_INTENT='{CR_PACKAGE}/{CR_ACTIVITY}',
      CR_TEST_RUNNER=os.path.join(
          '{CR_SRC}', 'build', 'android', 'test_runner.py'),
      CR_ADB_GDB=os.path.join('{CR_SRC}', 'build', 'android', 'adb_gdb'),
      CR_DEFAULT_TARGET='chrome_public',
      GYP_DEF_OS='android',
      GN_ARG_target_os='"android"'
  )

  def __init__(self):
    super(AndroidPlatform, self).__init__()
    self._env = cr.Config('android-env', literal=True, export=True)
    self.detected_config.AddChild(self._env)
    self._env_ready = False
    self._env_paths = []

  @property
  def priority(self):
    return super(AndroidPlatform, self).priority + 1

  def Prepare(self):
    """Override Prepare from cr.Platform."""
    super(AndroidPlatform, self).Prepare()
    try:
      # capture the result of env setup if we have not already done so
      if not self._env_ready:
        # See what the env would be without env setup
        before = cr.context.exported
        # Run env setup and capture/parse its output
        envsetup = 'source {CR_ENVSETUP}'
        output = cr.Host.CaptureShell(envsetup + ' > /dev/null && env')
        env_setup = cr.Config('envsetup', literal=True, export=True)
        for line in output.split('\n'):
          (key, op, value) = line.partition('=')
          if op:
            key = key.strip()
            if key not in _IGNORE_ENV:
              env_setup[key] = env_setup.ParseValue(value.strip())
            if key == 'PATH':
              self._env_paths = value.strip().split(os.path.pathsep)
        items = env_setup.exported.items()
        if not items:
          # Because of the way envsetup is run, the exit code does not make it
          # back to us. Instead, we assume if we got no environment at all, it
          # must have failed.
          print 'Envsetup failed!'
          exit(1)
        # Find all the things that envsetup changed
        for key, value in env_setup.exported.items():
          if str(value) != str(before.get(key, None)):
            self._env[key] = value
      self._env_ready = True
    except subprocess.CalledProcessError, e:
      exit(e.returncode)

  @property
  def paths(self):
    return self._env_paths


class AndroidInitHook(cr.InitHook):
  """Android output directory init hook.

  This makes sure that your client is android capable when you try
  to make and android output directory.
  """

  @property
  def enabled(self):
    return cr.AndroidPlatform.GetInstance().is_active

  def Run(self, old_version, config):
    _ = old_version, config  # unused
    # Check we are an android capable client
    target_os = cr.context.gclient.get('target_os', [])
    if 'android' in target_os:
      return
    url = cr.context.gclient.get('solutions', [{}])[0].get('url')
    if (url.startswith('https://chrome-internal.googlesource.com/') and
        url.endswith('/internal/apps.git')):
      return
    print 'This client is not android capable.'
    print 'It can be made capable by adding android to the target_os list'
    print 'in the .gclient file, and then syncing again.'
    if not cr.Host.YesNo('Would you like to upgrade this client?'):
      print 'Abandoning the creation of and android output directory.'
      exit(1)
    target_os.append('android')
    cr.context.gclient['target_os'] = target_os
    cr.base.client.WriteGClient()
    print 'Client updated.'
    print 'You may need to sync before an output directory can be made.'
    if cr.Host.YesNo('Would you like to sync this client now?'):
      cr.SyncCommand.Sync(["--nohooks"])


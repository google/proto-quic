# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import imp
import logging
import os
import pipes
import shlex

import devil_chromium
from devil.android import apk_helper
from devil.android import device_errors
from devil.android import device_utils
from devil.android import flag_changer
from devil.android.sdk import intent
from devil.android.sdk import adb_wrapper
from devil.utils import run_tests_helper

from pylib import constants


def _InstallApk(install_incremental, inc_install_script, devices_obj,
                apk_to_install):
  if install_incremental:
    helper = apk_helper.ApkHelper(apk_to_install)
    try:
      install_wrapper = imp.load_source('install_wrapper', inc_install_script)
    except IOError:
      raise Exception('Incremental install script not found: %s\n' %
                      inc_install_script)
    params = install_wrapper.GetInstallParameters()

    def install_incremental_apk(device):
      from incremental_install import installer
      installer.Install(device, helper, split_globs=params['splits'],
                        native_libs=params['native_libs'],
                        dex_files=params['dex_files'], permissions=None)
    devices_obj.pMap(install_incremental_apk)
  else:
    # Install the regular apk on devices.
    def install(device):
      device.Install(apk_to_install)
    devices_obj.pMap(install)


def _UninstallApk(install_incremental, devices_obj, apk_package):
  if install_incremental:
    def uninstall_incremental_apk(device):
      from incremental_install import installer
      installer.Uninstall(device, apk_package)
    devices_obj.pMap(uninstall_incremental_apk)
  else:
    # Uninstall the regular apk on devices.
    def uninstall(device):
      device.Uninstall(apk_package)
    devices_obj.pMap(uninstall)


def _LaunchUrl(devices_obj, input_args, device_args_file, url, apk_package):
  if input_args and device_args_file is None:
    raise Exception("This apk does not support any flags.")
  def launch(device):
    # The flags are first updated with input args.
    changer = flag_changer.FlagChanger(device, device_args_file)
    flags = []
    if input_args:
      flags = shlex.split(input_args)
    changer.ReplaceFlags(flags)
    # Then launch the apk.
    if url is None:
      # Simulate app icon click if no url is present.
      cmd = ['monkey', '-p', apk_package, '-c',
             'android.intent.category.LAUNCHER', '1']
      device.RunShellCommand(cmd, check_return=True)
    else:
      launch_intent = intent.Intent(
          action='android.intent.action.VIEW', package=apk_package, data=url)
      device.StartActivity(launch_intent)
  devices_obj.pMap(launch)


def _ChangeFlags(devices, devices_obj, input_args, device_args_file):
  if input_args is None:
    _DisplayArgs(devices, device_args_file)
  else:
    flags = shlex.split(input_args)
    def update(device):
      flag_changer.FlagChanger(device, device_args_file).ReplaceFlags(flags)
    devices_obj.pMap(update)


# TODO(Yipengw):add "--all" in the MultipleDevicesError message and use it here.
def _GenerateMissingAllFlagMessage(devices, devices_obj):
  descriptions = devices_obj.pMap(lambda d: d.build_description).pGet(None)
  msg = ('More than one device available. Use --all to select all devices, '
         'or use --device to select a device by serial.\n\nAvailable '
         'devices:\n')
  for d, desc in zip(devices, descriptions):
    msg += '  %s (%s)\n' % (d, desc)
  return msg


def _DisplayArgs(devices, device_args_file):
  print 'Existing flags per-device (via /data/local/tmp/%s):' % device_args_file
  for d in devices:
    changer = flag_changer.FlagChanger(d, device_args_file)
    flags = changer.GetCurrentFlags()
    if flags:
      quoted_flags = ' '.join(pipes.quote(f) for f in flags)
    else:
      quoted_flags = '( empty )'
    print '  %s (%s): %s' % (d, d.build_description, quoted_flags)


def _AddCommonOptions(parser):
  parser.add_argument('--all',
                      action='store_true',
                      default=False,
                      help='Operate on all connected devices.',)
  parser.add_argument('-d',
                      '--device',
                      action='append',
                      default=[],
                      dest='devices',
                      help='Target device for script to work on. Enter '
                           'multiple times for multiple devices.')
  parser.add_argument('--incremental',
                      action='store_true',
                      default=False,
                      help='Always install an incremental apk.')
  parser.add_argument('--non-incremental',
                      action='store_true',
                      default=False,
                      help='Always install a non-incremental apk.')
  parser.add_argument('-v',
                      '--verbose',
                      action='count',
                      default=0,
                      dest='verbose_count',
                      help='Verbose level (multiple times for more)')


def _AddLaunchOptions(parser):
  parser = parser.add_argument_group("launch arguments")
  parser.add_argument('url',
                      nargs='?',
                      help='The URL this command launches.')


def _AddArgsOptions(parser):
  parser = parser.add_argument_group("argv arguments")
  parser.add_argument('--args',
                      help='The flags set by the user.')


def _DeviceCachePath(device):
  file_name = 'device_cache_%s.json' % device.adb.GetDeviceSerial()
  return os.path.join(constants.GetOutDirectory(), file_name)


def Run(output_directory, apk_path, inc_apk_path, inc_install_script,
         command_line_flags_file):
  constants.SetOutputDirectory(output_directory)

  parser = argparse.ArgumentParser()
  command_parsers = parser.add_subparsers(title='Apk operations',
                                          dest='command')
  subp = command_parsers.add_parser('install', help='Install the apk.')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('uninstall', help='Uninstall the apk.')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('launch',
                                    help='Launches the apk with the given '
                                    'command-line flags, and optionally the '
                                    'given URL')
  _AddCommonOptions(subp)
  _AddLaunchOptions(subp)
  _AddArgsOptions(subp)

  subp = command_parsers.add_parser('run', help='Install and launch.')
  _AddCommonOptions(subp)
  _AddLaunchOptions(subp)
  _AddArgsOptions(subp)

  subp = command_parsers.add_parser('stop', help='Stop apks on all devices')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('clear-data',
                                    help='Clear states for the given package')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('argv',
                                    help='Display and update flags on devices.')
  _AddCommonOptions(subp)
  _AddArgsOptions(subp)

  subp = command_parsers.add_parser('gdb',
                                    help='Run build/android/adb_gdb script.')
  _AddCommonOptions(subp)
  _AddArgsOptions(subp)

  subp = command_parsers.add_parser('logcat',
                                    help='Run the shell command "adb logcat".')
  _AddCommonOptions(subp)

  args = parser.parse_args()
  run_tests_helper.SetLogLevel(args.verbose_count)
  command = args.command

  devil_chromium.Initialize()

  devices = device_utils.DeviceUtils.HealthyDevices(device_arg=args.devices,
                                                    default_retries=0)
  devices_obj = device_utils.DeviceUtils.parallel(devices)

  if command in {'gdb', 'logcat'} and len(devices) > 1:
    raise device_errors.MultipleDevicesError(devices)
  if command in {'argv', 'stop', 'clear-data'} or len(args.devices) > 0:
    args.all = True
  if len(devices) > 1 and not args.all:
    raise Exception(_GenerateMissingAllFlagMessage(devices, devices_obj))

  if args.incremental and args.non_incremental:
    raise Exception('--incremental and --non-incremental cannot be set at the '
                    'same time.')
  install_incremental = False
  active_apk = None
  apk_package = None
  apk_name = os.path.basename(apk_path)
  if apk_path and not os.path.exists(apk_path):
    apk_path = None

  if args.non_incremental:
    if apk_path:
      active_apk = apk_path
      logging.info('Use the non-incremental apk.')
    else:
      raise Exception("No regular apk is available.")

  if inc_apk_path and not os.path.exists(inc_apk_path):
    inc_apk_path = None

  if args.incremental:
    if inc_apk_path:
      active_apk = inc_apk_path
      install_incremental = True
      logging.info('Use the incremental apk.')
    else:
      raise Exception("No incremental apk is available.")

  if not args.incremental and not args.non_incremental and command in {
      'install', 'run'}:
    if apk_path and inc_apk_path:
      raise Exception('Both incremental and non-incremental apks exist, please '
                      'use --incremental or --non-incremental to select one.')
    if not apk_path and not inc_apk_path:
      raise Exception('Neither incremental nor non-incremental apk is '
                      'available.')
    if apk_path:
      active_apk = apk_path
      logging.info('Use the non-incremental apk.')
    else:
      active_apk = inc_apk_path
      install_incremental = True
      logging.info('Use the incremental apk.')

  if apk_path is not None:
    apk_package = apk_helper.GetPackageName(apk_path)
  elif inc_apk_path is not None:
    apk_package = apk_helper.GetPackageName(inc_apk_path)

  # Use the cache if possible.
  use_cache = True
  if command in {'gdb', 'logcat'}:
    # Only the current data is needed for these cmds.
    use_cache = False
  if use_cache:
    for d in devices:
      cache_path = _DeviceCachePath(d)
      if os.path.exists(cache_path):
        logging.info('Using device cache: %s', cache_path)
        with open(cache_path) as f:
          d.LoadCacheData(f.read())
        # Delete the cached file so that any exceptions cause it to be cleared.
        os.unlink(cache_path)
      else:
        logging.info('No cache present for device: %s', d)

  if command == 'install':
    _InstallApk(install_incremental, inc_install_script, devices_obj,
                active_apk)
  elif command == 'uninstall':
    _UninstallApk(install_incremental, devices_obj, apk_package)
  elif command == 'launch':
    _LaunchUrl(devices_obj, args.args, command_line_flags_file,
               args.url, apk_package)
  elif command == 'run':
    _InstallApk(install_incremental, inc_install_script, devices_obj,
                active_apk)
    devices_obj.pFinish(None)
    _LaunchUrl(devices_obj, args.args, command_line_flags_file,
               args.url, apk_package)
  elif command == 'stop':
    devices_obj.ForceStop(apk_package)
  elif command == 'clear-data':
    devices_obj.ClearApplicationState(apk_package)
  elif command == 'argv':
    _ChangeFlags(devices, devices_obj, args.args,
                 command_line_flags_file)
  elif command == 'gdb':
    gdb_script_path = os.path.dirname(__file__) + '/adb_gdb'
    program_name = '--program-name=%s' % os.path.splitext(apk_name)[0]
    package_name = '--package-name=%s' % apk_package
    # The output directory is the one including lib* files.
    output_dir = '--output-directory=%s' % os.path.abspath(
        os.path.join(output_directory, os.pardir))
    adb_path = '--adb=%s' % adb_wrapper.AdbWrapper.GetAdbPath()
    device = '--device=%s' % devices[0].adb.GetDeviceSerial()
    flags = [gdb_script_path, program_name, package_name, output_dir, adb_path,
             device]
    if args.args:
      flags += shlex.split(args.args)
    # Enable verbose output of adb_gdb if it's set for this script.
    if args.verbose_count > 0:
      flags.append('--verbose')
    logging.warning('Running: %s', ' '.join(pipes.quote(f) for f in flags))
    os.execv(gdb_script_path, flags)
  elif command == 'logcat':
    adb_path = adb_wrapper.AdbWrapper.GetAdbPath()
    flags = [adb_path, '-s', devices[0].adb.GetDeviceSerial(), 'logcat']
    os.execv(adb_path, flags)

  # Wait for all threads to finish.
  devices_obj.pFinish(None)

  # Save back to the cache.
  if use_cache:
    for d in devices:
      cache_path = _DeviceCachePath(d)
      with open(cache_path, 'w') as f:
        f.write(d.DumpCacheData())
        logging.info('Wrote device cache: %s', cache_path)

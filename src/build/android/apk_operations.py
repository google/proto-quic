# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import json
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

from incremental_install import installer
from pylib import constants


def _InstallApk(apk, install_dict, devices_obj):
  def install(device):
    if install_dict:
      installer.Install(device, install_dict, apk=apk)
    else:
      device.Install(apk)
  devices_obj.pMap(install)


def _UninstallApk(install_dict, devices_obj, apk_package):
  def uninstall(device):
    if install_dict:
      installer.Uninstall(device, apk_package)
    else:
      device.Uninstall(apk_package)
  devices_obj.pMap(uninstall)


def _LaunchUrl(devices_obj, input_args, device_args_file, url, apk):
  if input_args and device_args_file is None:
    raise Exception('This apk does not support any flags.')
  if url:
    view_activity = apk.GetViewActivityName()
    if not view_activity:
      raise Exception('APK does not support launching with URLs.')

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
      cmd = ['monkey', '-p', apk.GetPackageName(), '-c',
             'android.intent.category.LAUNCHER', '1']
      device.RunShellCommand(cmd, check_return=True)
    else:
      launch_intent = intent.Intent(action='android.intent.action.VIEW',
                                    activity=view_activity, data=url,
                                    package=apk.GetPackageName())
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


def _SelectApk(apk_path, incremental_install_json_path, parser, args):
  if apk_path and not os.path.exists(apk_path):
    apk_path = None
  if (incremental_install_json_path and
      not os.path.exists(incremental_install_json_path)):
    incremental_install_json_path = None

  if args.incremental and args.non_incremental:
    parser.error('--incremental and --non-incremental cannot both be used.')
  elif args.non_incremental:
    if not apk_path:
      parser.error('Apk has not been built.')
    incremental_install_json_path = None
  elif args.incremental:
    if not incremental_install_json_path:
      parser.error('Incremental apk has not been built.')
    apk_path = None

  if args.command in ('install', 'run'):
    if apk_path and incremental_install_json_path:
      parser.error('Both incremental and non-incremental apks exist, please '
                   'use --incremental or --non-incremental to select one.')
    elif apk_path:
      logging.info('Using the non-incremental apk.')
    elif incremental_install_json_path:
      logging.info('Using the incremental apk.')
    else:
      parser.error('Neither incremental nor non-incremental apk is built.')
  return apk_path, incremental_install_json_path


def _LoadDeviceCaches(devices):
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


def _SaveDeviceCaches(devices):
  for d in devices:
    cache_path = _DeviceCachePath(d)
    with open(cache_path, 'w') as f:
      f.write(d.DumpCacheData())
      logging.info('Wrote device cache: %s', cache_path)


def Run(output_directory, apk_path, incremental_install_json_path,
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
  # Enable caching unless executing a helper script (where we won't get a chance
  # to update the cache afterwards).
  use_cache = command not in {'gdb', 'logcat'}

  devil_chromium.Initialize()

  devices = device_utils.DeviceUtils.HealthyDevices(
      device_arg=args.devices,
      enable_device_files_cache=use_cache,
      default_retries=0)
  devices_obj = device_utils.DeviceUtils.parallel(devices)

  if command in {'gdb', 'logcat'} and len(devices) > 1:
    raise device_errors.MultipleDevicesError(devices)
  if command in {'argv', 'stop', 'clear-data'} or len(args.devices) > 0:
    args.all = True
  if len(devices) > 1 and not args.all:
    raise Exception(_GenerateMissingAllFlagMessage(devices, devices_obj))

  apk_name = os.path.basename(apk_path)
  apk_path, incremental_install_json_path = _SelectApk(
      apk_path, incremental_install_json_path, parser, args)
  install_dict = None

  if incremental_install_json_path:
    with open(incremental_install_json_path) as f:
      install_dict = json.load(f)
    apk = apk_helper.ToHelper(
        os.path.join(output_directory, install_dict['apk_path']))
  else:
    apk = apk_helper.ToHelper(apk_path)

  apk_package = apk.GetPackageName()

  if use_cache:
    _LoadDeviceCaches(devices)

  if command == 'install':
    _InstallApk(apk, install_dict, devices_obj)
  elif command == 'uninstall':
    _UninstallApk(install_dict, devices_obj, apk_package)
  elif command == 'launch':
    _LaunchUrl(devices_obj, args.args, command_line_flags_file,
               args.url, apk)
  elif command == 'run':
    logging.warning('Installing...')
    _InstallApk(apk, install_dict, devices_obj)
    logging.warning('Sending launch intent...')
    _LaunchUrl(devices_obj, args.args, command_line_flags_file,
               args.url, apk)
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
    output_dir = '--output-directory=%s' % output_directory
    adb_path = '--adb=%s' % adb_wrapper.AdbWrapper.GetAdbPath()
    device = '--device=%s' % devices[0].adb.GetDeviceSerial()
    # Use one lib dir per device so that changing between devices does require
    # refetching the device libs.
    libs_dir = '--pull-libs-dir=/tmp/adb-gdb-libs-%s' % (
        devices[0].adb.GetDeviceSerial())
    flags = [gdb_script_path, program_name, package_name, output_dir, device,
             adb_path, libs_dir]
    if args.args:
      flags += shlex.split(args.args)
    # Enable verbose output of adb_gdb if it's set for this script.
    if args.verbose_count > 0:
      flags.append('--verbose')
    logging.warning('Running: %s', ' '.join(pipes.quote(f) for f in flags))
    logging.warning('All subsequent output is from adb_gdb script.')
    os.execv(gdb_script_path, flags)
  elif command == 'logcat':
    adb_path = adb_wrapper.AdbWrapper.GetAdbPath()
    flags = [adb_path, '-s', devices[0].adb.GetDeviceSerial(), 'logcat']
    os.execv(adb_path, flags)

  # Save back to the cache.
  if use_cache:
    _SaveDeviceCaches(devices)

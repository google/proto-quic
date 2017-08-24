# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import json
import logging
import os
import pipes
import posixpath
import re
import shlex
import sys

import devil_chromium
from devil import devil_env
from devil.android import apk_helper
from devil.android import device_errors
from devil.android import device_utils
from devil.android import flag_changer
from devil.android.sdk import adb_wrapper
from devil.android.sdk import intent
from devil.android.sdk import version_codes
from devil.utils import run_tests_helper

with devil_env.SysPath(os.path.join(os.path.dirname(__file__), '..', '..',
                                    'third_party', 'colorama', 'src')):
  import colorama

from incremental_install import installer
from pylib import constants


def _Colorize(color, text):
  # |color| as a string to avoid pylint's no-member warning :(.
  # pylint: disable=no-member
  return getattr(colorama.Fore, color) + text + colorama.Fore.RESET


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
    _DisplayArgs(devices, devices_obj, device_args_file)
  else:
    flags = shlex.split(input_args)
    def update(device):
      flag_changer.FlagChanger(device, device_args_file).ReplaceFlags(flags)
    devices_obj.pMap(update)


def _TargetCpuToTargetArch(target_cpu):
  if target_cpu == 'x64':
    return 'x86_64'
  if target_cpu == 'mipsel':
    return 'mips'
  return target_cpu


def _RunGdb(apk_name, apk_package, device, target_cpu, extra_args, verbose):
  gdb_script_path = os.path.dirname(__file__) + '/adb_gdb'
  cmd = [
      gdb_script_path,
      '--program-name=%s' % os.path.splitext(apk_name)[0],
      '--package-name=%s' % apk_package,
      '--output-directory=%s' % constants.GetOutDirectory(),
      '--adb=%s' % adb_wrapper.AdbWrapper.GetAdbPath(),
      '--device=%s' % device.serial,
      # Use one lib dir per device so that changing between devices does require
      # refetching the device libs.
      '--pull-libs-dir=/tmp/adb-gdb-libs-%s' % device.serial,
  ]
  # Enable verbose output of adb_gdb if it's set for this script.
  if verbose:
    cmd.append('--verbose')
  if target_cpu:
    cmd.append('--target-arch=%s' % _TargetCpuToTargetArch(target_cpu))
  cmd.extend(extra_args)
  logging.warning('Running: %s', ' '.join(pipes.quote(x) for x in cmd))
  print _Colorize('YELLOW', 'All subsequent output is from adb_gdb script.')
  os.execv(gdb_script_path, cmd)


def _PrintPerDeviceOutput(devices, results, single_line=False):
  for d, result in zip(devices, results):
    if not single_line and d is not devices[0]:
      sys.stdout.write('\n')
    sys.stdout.write(
          _Colorize('YELLOW', '%s (%s):' % (d, d.build_description)))
    sys.stdout.write(' ' if single_line else '\n')
    yield result


def _RunMemUsage(devices, devices_obj, apk_package):
  def mem_usage_helper(d):
    ret = []
    proc_map = d.GetPids(apk_package)
    for name, pids in proc_map.iteritems():
      for pid in pids:
        ret.append((name, pid, d.GetMemoryUsageForPid(pid)))
    return ret

  all_results = devices_obj.pMap(mem_usage_helper).pGet(None)
  for result in _PrintPerDeviceOutput(devices, all_results):
    if not result:
      print 'No processes found.'
    else:
      for name, pid, usage in sorted(result):
        print '%s(%s):' % (name, pid)
        for k, v in sorted(usage.iteritems()):
          print '    %s=%d' % (k, v)
        print


def _DuHelper(device, path_spec, run_as=None):
  """Runs "du -s -k |path_spec|" on |device| and returns parsed result.

  Args:
    device: A DeviceUtils instance.
    path_spec: The list of paths to run du on. May contain shell expansions
        (will not be escaped).
    run_as: Package name to run as, or None to run as shell user. If not None
        and app is not android:debuggable (run-as fails), then command will be
        run as root.

  Returns:
    A dict of path->size in kb containing all paths in |path_spec| that exist on
    device. Paths that do not exist are silently ignored.
  """
  # Example output for: du -s -k /data/data/org.chromium.chrome/{*,.*}
  # 144     /data/data/org.chromium.chrome/cache
  # 8       /data/data/org.chromium.chrome/files
  # <snip>
  # du: .*: No such file or directory

  # The -d flag works differently across android version, so use -s instead.
  cmd_str = 'du -s -k ' + path_spec
  lines = device.RunShellCommand(cmd_str, run_as=run_as, shell=True,
                                 check_return=False)
  output = '\n'.join(lines)
  # run-as: Package 'com.android.chrome' is not debuggable
  if output.startswith('run-as:'):
    # check_return=False needed for when some paths in path_spec do not exist.
    lines = device.RunShellCommand(cmd_str, as_root=True, shell=True,
                                   check_return=False)
  ret = {}
  try:
    for line in lines:
      # du: .*: No such file or directory
      if line.startswith('du:'):
        continue
      size, subpath = line.split(None, 1)
      ret[subpath] = int(size)
    return ret
  except ValueError:
    logging.error('Failed to parse du output:\n%s', output)


def _RunDiskUsage(devices, devices_obj, apk_package, verbose):
  # Measuring dex size is a bit complicated:
  # https://source.android.com/devices/tech/dalvik/jit-compiler
  #
  # For KitKat and below:
  #   dumpsys package contains:
  #     dataDir=/data/data/org.chromium.chrome
  #     codePath=/data/app/org.chromium.chrome-1.apk
  #     resourcePath=/data/app/org.chromium.chrome-1.apk
  #     nativeLibraryPath=/data/app-lib/org.chromium.chrome-1
  #   To measure odex:
  #     ls -l /data/dalvik-cache/data@app@org.chromium.chrome-1.apk@classes.dex
  #
  # For Android L and M (and maybe for N+ system apps):
  #   dumpsys package contains:
  #     codePath=/data/app/org.chromium.chrome-1
  #     resourcePath=/data/app/org.chromium.chrome-1
  #     legacyNativeLibraryDir=/data/app/org.chromium.chrome-1/lib
  #   To measure odex:
  #     # Option 1:
  #  /data/dalvik-cache/arm/data@app@org.chromium.chrome-1@base.apk@classes.dex
  #  /data/dalvik-cache/arm/data@app@org.chromium.chrome-1@base.apk@classes.vdex
  #     ls -l /data/dalvik-cache/profiles/org.chromium.chrome
  #         (these profiles all appear to be 0 bytes)
  #     # Option 2:
  #     ls -l /data/app/org.chromium.chrome-1/oat/arm/base.odex
  #
  # For Android N+:
  #   dumpsys package contains:
  #     dataDir=/data/user/0/org.chromium.chrome
  #     codePath=/data/app/org.chromium.chrome-UuCZ71IE-i5sZgHAkU49_w==
  #     resourcePath=/data/app/org.chromium.chrome-UuCZ71IE-i5sZgHAkU49_w==
  #     legacyNativeLibraryDir=/data/app/org.chromium.chrome-GUID/lib
  #     Instruction Set: arm
  #       path: /data/app/org.chromium.chrome-UuCZ71IE-i5sZgHAkU49_w==/base.apk
  #       status: /data/.../oat/arm/base.odex[status=kOatUpToDate, compilation_f
  #       ilter=quicken]
  #     Instruction Set: arm64
  #       path: /data/app/org.chromium.chrome-UuCZ71IE-i5sZgHAkU49_w==/base.apk
  #       status: /data/.../oat/arm64/base.odex[status=..., compilation_filter=q
  #       uicken]
  #   To measure odex:
  #     ls -l /data/app/.../oat/arm/base.odex
  #     ls -l /data/app/.../oat/arm/base.vdex (optional)
  #   To measure the correct odex size:
  #     cmd package compile -m speed org.chromium.chrome  # For webview
  #     cmd package compile -m speed-profile org.chromium.chrome  # For others
  def disk_usage_helper(d):
    package_output = '\n'.join(d.RunShellCommand(
        ['dumpsys', 'package', apk_package], check_return=True))
    # Prints a message but does not return error when apk is not installed.
    if 'Unable to find package:' in package_output:
      return None
    # Ignore system apks.
    idx = package_output.find('Hidden system packages:')
    if idx != -1:
      package_output = package_output[:idx]

    try:
      data_dir = re.search(r'dataDir=(.*)', package_output).group(1)
      code_path = re.search(r'codePath=(.*)', package_output).group(1)
      lib_path = re.search(r'(?:legacyN|n)ativeLibrary(?:Dir|Path)=(.*)',
                           package_output).group(1)
    except AttributeError:
      raise Exception('Error parsing dumpsys output: ' + package_output)
    compilation_filters = set()
    # Match "compilation_filter=value", where a line break can occur at any spot
    # (refer to examples above).
    awful_wrapping = r'\s*'.join('compilation_filter=')
    for m in re.finditer(awful_wrapping + r'([\s\S]+?)[\],]', package_output):
      compilation_filters.add(re.sub(r'\s+', '', m.group(1)))
    compilation_filter = ','.join(sorted(compilation_filters))

    data_dir_sizes = _DuHelper(d, '%s/{*,.*}' % data_dir, run_as=apk_package)
    # Measure code_cache separately since it can be large.
    code_cache_sizes = {}
    code_cache_dir = next(
        (k for k in data_dir_sizes if k.endswith('/code_cache')), None)
    if code_cache_dir:
      data_dir_sizes.pop(code_cache_dir)
      code_cache_sizes = _DuHelper(d, '%s/{*,.*}' % code_cache_dir,
                                   run_as=apk_package)

    apk_path_spec = code_path
    if not apk_path_spec.endswith('.apk'):
      apk_path_spec += '/*.apk'
    apk_sizes = _DuHelper(d, apk_path_spec)
    if lib_path.endswith('/lib'):
      # Shows architecture subdirectory.
      lib_sizes = _DuHelper(d, '%s/{*,.*}' % lib_path)
    else:
      lib_sizes = _DuHelper(d, lib_path)

    # Look at all possible locations for odex files.
    odex_paths = []
    for apk_path in apk_sizes:
      mangled_apk_path = apk_path[1:].replace('/', '@')
      apk_basename = posixpath.basename(apk_path)[:-4]
      for ext in ('dex', 'odex', 'vdex', 'art'):
        # Easier to check all architectures than to determine active ones.
        for arch in ('arm', 'arm64', 'x86', 'x86_64', 'mips', 'mips64'):
          odex_paths.append(
              '%s/oat/%s/%s.%s' % (code_path, arch, apk_basename, ext))
          # No app could possibly have more than 6 dex files.
          for suffix in ('', '2', '3', '4', '5'):
            odex_paths.append('/data/dalvik-cache/%s/%s@classes%s.%s' % (
                arch, mangled_apk_path, suffix, ext))
            # This path does not have |arch|, so don't repeat it for every arch.
            if arch == 'arm':
              odex_paths.append('/data/dalvik-cache/%s@classes%s.dex' % (
                  mangled_apk_path, suffix))

    odex_sizes = _DuHelper(d, ' '.join(pipes.quote(p) for p in odex_paths))

    return (data_dir_sizes, code_cache_sizes, apk_sizes, lib_sizes, odex_sizes,
            compilation_filter)

  def print_sizes(desc, sizes):
    print '%s: %dkb' % (desc, sum(sizes.itervalues()))
    if verbose:
      for path, size in sorted(sizes.iteritems()):
        print '    %s: %skb' % (path, size)

  all_results = devices_obj.pMap(disk_usage_helper).pGet(None)
  for result in _PrintPerDeviceOutput(devices, all_results):
    if not result:
      print 'APK is not installed.'
      continue

    (data_dir_sizes, code_cache_sizes, apk_sizes, lib_sizes, odex_sizes,
     compilation_filter) = result
    total = sum(sum(sizes.itervalues()) for sizes in result[:-1])

    print_sizes('Apk', apk_sizes)
    print_sizes('App Data (non-code cache)', data_dir_sizes)
    print_sizes('App Data (code cache)', code_cache_sizes)
    print_sizes('Native Libs', lib_sizes)
    show_warning = compilation_filter and 'speed' not in compilation_filter
    compilation_filter = compilation_filter or 'n/a'
    print_sizes('odex (compilation_filter=%s)' % compilation_filter, odex_sizes)
    if show_warning:
      logging.warning('For a more realistic odex size, run:')
      logging.warning('    %s compile-dex [speed|speed-profile]', sys.argv[0])
    print 'Total: %skb (%.1fmb)' % (total, total / 1024.0)


def _RunPs(devices, devices_obj, apk_package):
  all_pids = devices_obj.GetPids(apk_package).pGet(None)
  for proc_map in _PrintPerDeviceOutput(devices, all_pids):
    if not proc_map:
      print 'No processes found.'
    else:
      for name, pids in sorted(proc_map.items()):
        print name, ','.join(pids)


def _RunShell(devices, devices_obj, apk_package, cmd):
  if cmd:
    outputs = devices_obj.RunShellCommand(cmd, run_as=apk_package).pGet(None)
    for output in _PrintPerDeviceOutput(devices, outputs):
      for line in output:
        print line
  else:
    adb_path = adb_wrapper.AdbWrapper.GetAdbPath()
    cmd = [adb_path, '-s', devices[0].serial, 'shell']
    # Pre-N devices do not support -t flag.
    if devices[0].build_version_sdk >= version_codes.NOUGAT:
      cmd += ['-t', 'run-as', apk_package]
    else:
      print 'Upon entering the shell, run:'
      print 'run-as', apk_package
      print
    os.execv(adb_path, cmd)


def _RunCompileDex(devices, devices_obj, apk_package, compilation_filter):
  cmd = ['cmd', 'package', 'compile', '-f', '-m', compilation_filter,
         apk_package]
  outputs = devices_obj.RunShellCommand(cmd).pGet(None)
  for output in _PrintPerDeviceOutput(devices, outputs):
    for line in output:
      print line


# TODO(Yipengw):add "--all" in the MultipleDevicesError message and use it here.
def _GenerateMissingAllFlagMessage(devices, devices_obj):
  descriptions = devices_obj.pMap(lambda d: d.build_description).pGet(None)
  msg = ('More than one device available. Use --all to select all devices, '
         'or use --device to select a device by serial.\n\nAvailable '
         'devices:\n')
  for d, desc in zip(devices, descriptions):
    msg += '  %s (%s)\n' % (d, desc)
  return msg


def _DisplayArgs(devices, devices_obj, device_args_file):
  def flags_helper(d):
    changer = flag_changer.FlagChanger(d, device_args_file)
    return changer.GetCurrentFlags()

  outputs = devices_obj.pMap(flags_helper).pGet(None)
  print 'Existing flags per-device (via /data/local/tmp/%s):' % device_args_file
  for flags in _PrintPerDeviceOutput(devices, outputs, single_line=True):
    quoted_flags = ' '.join(pipes.quote(f) for f in flags)
    print quoted_flags or 'No flags set.'


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
  parser.add_argument('-v',
                      '--verbose',
                      action='count',
                      default=0,
                      dest='verbose_count',
                      help='Verbose level (multiple times for more)')


def _AddInstallOptions(parser):
  parser = parser.add_argument_group('install arguments')
  parser.add_argument('--incremental',
                      action='store_true',
                      default=False,
                      help='Always install an incremental apk.')
  parser.add_argument('--non-incremental',
                      action='store_true',
                      default=False,
                      help='Always install a non-incremental apk.')


def _AddLaunchOptions(parser):
  parser = parser.add_argument_group('launch arguments')
  parser.add_argument('url',
                      nargs='?',
                      help='The URL this command launches.')


def _AddArgsOptions(parser):
  parser = parser.add_argument_group('argv arguments')
  parser.add_argument('--args',
                      help='The flags set by the user.')


def _DeviceCachePath(device):
  file_name = 'device_cache_%s.json' % device.serial
  return os.path.join(constants.GetOutDirectory(), file_name)


def _SelectApk(apk_path, incremental_install_json_path, parser, args):
  if apk_path and not os.path.exists(apk_path):
    apk_path = None
  if (incremental_install_json_path and
      not os.path.exists(incremental_install_json_path)):
    incremental_install_json_path = None

  if args.command in ('install', 'run'):
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
      logging.debug('Using device cache: %s', cache_path)
      with open(cache_path) as f:
        d.LoadCacheData(f.read())
      # Delete the cached file so that any exceptions cause it to be cleared.
      os.unlink(cache_path)
    else:
      logging.debug('No cache present for device: %s', d)


def _SaveDeviceCaches(devices):
  for d in devices:
    cache_path = _DeviceCachePath(d)
    with open(cache_path, 'w') as f:
      f.write(d.DumpCacheData())
      logging.info('Wrote device cache: %s', cache_path)


# target_cpu=None so that old wrapper scripts continue to work without
# the need for a rebuild.
def Run(output_directory, apk_path, incremental_install_json_path,
        command_line_flags_file, target_cpu=None):
  colorama.init()
  constants.SetOutputDirectory(output_directory)

  parser = argparse.ArgumentParser()
  command_parsers = parser.add_subparsers(title='Apk operations',
                                          dest='command')
  subp = command_parsers.add_parser('install', help='Install the apk.')
  _AddCommonOptions(subp)
  _AddInstallOptions(subp)

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
  _AddInstallOptions(subp)
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

  subp = command_parsers.add_parser('disk-usage',
      help='Display disk usage for the APK.')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('mem-usage',
      help='Display memory usage of currently running APK processes.')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('ps',
      help='Shows PIDs of any APK processes currently running.')
  _AddCommonOptions(subp)

  subp = command_parsers.add_parser('shell',
      help='Same as "adb shell <command>", but runs as the apk\'s uid (via '
           'run-as). Useful for inspecting the app\'s data directory.')
  _AddCommonOptions(subp)
  group = subp.add_argument_group('shell arguments')
  group.add_argument('cmd', nargs=argparse.REMAINDER, help='Command to run.')

  subp = command_parsers.add_parser('compile-dex',
      help='Applicable only for Android N+. Forces .odex files to be compiled '
           'with the given compilation filter. To see existing filter, use '
           '"disk-usage" command.')
  _AddCommonOptions(subp)
  group = subp.add_argument_group('compile-dex arguments')
  # Allow only the most useful subset of filters.
  group.add_argument('compilation_filter',
                     choices=['verify', 'quicken', 'space-profile', 'space',
                              'speed-profile', 'speed'],
                     help='For WebView/Monochrome, use "speed". '
                          'For other apks, use "speed-profile".')

  # Show extended help when no command is passed.
  argv = sys.argv[1:]
  if not argv:
    argv = ['--help']
  args = parser.parse_args(argv)
  run_tests_helper.SetLogLevel(args.verbose_count)
  command = args.command

  devil_chromium.Initialize()

  devices = device_utils.DeviceUtils.HealthyDevices(
      device_arg=args.devices,
      enable_device_files_cache=True,
      default_retries=0)
  devices_obj = device_utils.DeviceUtils.parallel(devices)
  _LoadDeviceCaches(devices)

  try:
    if len(devices) > 1:
      if command in ('gdb', 'logcat') or command == 'shell' and not args.cmd:
        raise device_errors.MultipleDevicesError(devices)
    default_all = command in ('argv', 'stop', 'clear-data', 'disk-usage',
                              'mem-usage', 'ps', 'compile-dex')
    if default_all or args.devices:
      args.all = True
    if len(devices) > 1 and not args.all:
      raise Exception(_GenerateMissingAllFlagMessage(devices, devices_obj))
  except:
    _SaveDeviceCaches(devices)
    raise

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

  # These commands use os.exec(), so we won't get a chance to update the cache
  # afterwards.
  if command in ('gdb', 'logcat', 'shell'):
    _SaveDeviceCaches(devices)

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
    extra_args = shlex.split(args.args or '')
    _RunGdb(apk_name, apk_package, devices[0], target_cpu, extra_args,
            args.verbose_count)
  elif command == 'logcat':
    adb_path = adb_wrapper.AdbWrapper.GetAdbPath()
    cmd = [adb_path, '-s', devices[0].serial, 'logcat']
    os.execv(adb_path, cmd)
  elif command == 'mem-usage':
    _RunMemUsage(devices, devices_obj, apk_package)
  elif command == 'disk-usage':
    _RunDiskUsage(devices, devices_obj, apk_package, args.verbose_count)
  elif command == 'ps':
    _RunPs(devices, devices_obj, apk_package)
  elif command == 'shell':
    _RunShell(devices, devices_obj, apk_package, args.cmd)
  elif command == 'compile-dex':
    _RunCompileDex(devices, devices_obj, apk_package, args.compilation_filter)

  # Save back to the cache.
  _SaveDeviceCaches(devices)

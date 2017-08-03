#!/usr/bin/env python
#
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Packages a user.bootfs for a Fuchsia boot image, pulling in the runtime
dependencies of a test binary, and then uses either QEMU from the Fuchsia SDK
to run, or starts the bootserver to allow running on a hardware device."""

import argparse
import multiprocessing
import os
import re
import signal
import subprocess
import sys
import tempfile


DIR_SOURCE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
SDK_ROOT = os.path.join(DIR_SOURCE_ROOT, 'third_party', 'fuchsia-sdk')
SYMBOLIZATION_TIMEOUT_SECS = 10


def RunAndCheck(dry_run, args):
  if dry_run:
    print 'Run:', args
  else:
    subprocess.check_call(args)


def DumpFile(dry_run, name, description):
  """Prints out the contents of |name| if |dry_run|."""
  if not dry_run:
    return
  print
  print 'Contents of %s (for %s)' % (name, description)
  print '-' * 80
  with open(name) as f:
    sys.stdout.write(f.read())
  print '-' * 80


def MakeTargetImageName(common_prefix, output_directory, location):
  """Generates the relative path name to be used in the file system image.
  common_prefix: a prefix of both output_directory and location that
                 be removed.
  output_directory: an optional prefix on location that will also be removed.
  location: the file path to relativize.

  .so files will be stored into the lib subdirectory to be able to be found by
  default by the loader.

  Examples:

  >>> MakeTargetImageName(common_prefix='/work/cr/src/',
  ...                     output_directory='/work/cr/src/out/fuch',
  ...                     location='/work/cr/src/base/test/data/xyz.json')
  'base/test/data/xyz.json'

  >>> MakeTargetImageName(common_prefix='/work/cr/src/',
  ...                     output_directory='/work/cr/src/out/fuch',
  ...                     location='/work/cr/src/out/fuch/icudtl.dat')
  'icudtl.dat'

  >>> MakeTargetImageName(common_prefix='/work/cr/src/',
  ...                     output_directory='/work/cr/src/out/fuch',
  ...                     location='/work/cr/src/out/fuch/libbase.so')
  'lib/libbase.so'
  """
  assert output_directory.startswith(common_prefix)
  output_dir_no_common_prefix = output_directory[len(common_prefix):]
  assert location.startswith(common_prefix)
  loc = location[len(common_prefix):]
  if loc.startswith(output_dir_no_common_prefix):
    loc = loc[len(output_dir_no_common_prefix)+1:]
  # TODO(fuchsia): The requirements for finding/loading .so are in flux, so this
  # ought to be reconsidered at some point. See https://crbug.com/732897.
  if location.endswith('.so'):
    loc = 'lib/' + loc
  return loc


def AddToManifest(manifest_file, target_name, source, mapper):
  """Appends |source| to the given |manifest_file| (a file object) in a format
  suitable for consumption by mkbootfs.

  If |source| is a file it's directly added. If |source| is a directory, its
  contents are recursively added.

  |source| must exist on disk at the time this function is called.
  """
  if os.path.isdir(source):
    files = [os.path.join(dp, f) for dp, dn, fn in os.walk(source) for f in fn]
    for f in files:
      # We pass None as the mapper because this should never recurse a 2nd time.
      AddToManifest(manifest_file, mapper(f), f, None)
  elif os.path.exists(source):
    manifest_file.write('%s=%s\n' % (target_name, source))
  else:
    raise Exception('%s does not exist' % source)


def BuildBootfs(output_directory, runtime_deps_path, test_name, child_args,
                test_launcher_filter_file, device, dry_run):
  with open(runtime_deps_path) as f:
    lines = f.readlines()

  locations_to_add = [os.path.abspath(os.path.join(output_directory, x.strip()))
                      for x in lines]
  locations_to_add.append(
      os.path.abspath(os.path.join(output_directory, test_name)))

  common_prefix = os.path.commonprefix(locations_to_add)
  target_source_pairs = zip(
      [MakeTargetImageName(common_prefix, output_directory, loc)
       for loc in locations_to_add],
      locations_to_add)

  if test_launcher_filter_file:
    test_launcher_filter_file = os.path.normpath(
            os.path.join(output_directory, test_launcher_filter_file))
    filter_file_on_device = MakeTargetImageName(
          common_prefix, output_directory, test_launcher_filter_file)
    child_args.append('--test-launcher-filter-file=/system/' +
                       filter_file_on_device)
    target_source_pairs.append(
        [filter_file_on_device, test_launcher_filter_file])

  # Generate a little script that runs the test binaries and then shuts down
  # QEMU.
  autorun_file = tempfile.NamedTemporaryFile()
  autorun_file.write('#!/bin/sh\n')
  autorun_file.write('/system/' + os.path.basename(test_name))

  for arg in child_args:
    autorun_file.write(' "%s"' % arg);

  autorun_file.write('\n')
  if not device:
    # If shutdown of QEMU happens too soon after the test completion, log
    # statements from the end of the run will be lost, so sleep for a bit before
    # shutting down. When running on device don't power off so the output and
    # system can be inspected.
    autorun_file.write('msleep 3000\n')
    autorun_file.write('dm poweroff\n')
  autorun_file.flush()
  os.chmod(autorun_file.name, 0750)
  DumpFile(dry_run, autorun_file.name, 'autorun')
  target_source_pairs.append(('autorun', autorun_file.name))

  manifest_file = tempfile.NamedTemporaryFile()
  bootfs_name = runtime_deps_path + '.bootfs'

  for target, source in target_source_pairs:
    AddToManifest(manifest_file.file, target, source,
                  lambda x: MakeTargetImageName(
                                common_prefix, output_directory, x))

  mkbootfs_path = os.path.join(SDK_ROOT, 'tools', 'mkbootfs')

  manifest_file.flush()
  DumpFile(dry_run, manifest_file.name, 'manifest')
  RunAndCheck(dry_run,
              [mkbootfs_path, '-o', bootfs_name,
               '--target=boot', os.path.join(SDK_ROOT, 'bootdata.bin'),
               '--target=system', manifest_file.name,
              ])
  return bootfs_name


def SymbolizeEntry(entry):
  addr2line_output = subprocess.check_output(
      ['addr2line', '-Cipf', '--exe=' + entry[1], entry[2]])
  prefix = '#%s: ' % entry[0]
  # addr2line outputs a second line for inlining information, offset
  # that to align it properly after the frame index.
  addr2line_filtered = addr2line_output.strip().replace(
      '(inlined', ' ' * len(prefix) + '(inlined')
  return '#%s: %s' % (prefix, addr2line_filtered)


def ParallelSymbolizeBacktrace(backtrace):
  # Disable handling of SIGINT during sub-process creation, to prevent
  # sub-processes from consuming Ctrl-C signals, rather than the parent
  # process doing so.
  saved_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
  p = multiprocessing.Pool(multiprocessing.cpu_count())

  # Restore the signal handler for the parent process.
  signal.signal(signal.SIGINT, saved_sigint_handler)

  symbolized = []
  try:
    result = p.map_async(SymbolizeEntry, backtrace)
    symbolized = result.get(SYMBOLIZATION_TIMEOUT_SECS)
    if not symbolized:
      return []
  except multiprocessing.TimeoutError:
    return ['(timeout error occurred during symbolization)']
  except KeyboardInterrupt:  # SIGINT
    p.terminate()

  return symbolized


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--dry-run', '-n', action='store_true', default=False,
                      help='Just print commands, don\'t execute them.')
  parser.add_argument('--output-directory',
                      type=os.path.realpath,
                      help=('Path to the directory in which build files are'
                            ' located (must include build type).'))
  parser.add_argument('--runtime-deps-path',
                      type=os.path.realpath,
                      help='Runtime data dependency file from GN.')
  parser.add_argument('--test-name',
                      type=os.path.realpath,
                      help='Name of the the test')
  parser.add_argument('--gtest_filter',
                      help='GTest filter to use in place of any default.')
  parser.add_argument('--gtest_repeat',
                      help='GTest repeat value to use.')
  parser.add_argument('--single-process-tests', action='store_true',
                      default=False,
                      help='Runs the tests and the launcher in the same '
                      'process. Useful for debugging.')
  parser.add_argument('--test-launcher-batch-limit',
                      type=int,
                      help='Sets the limit of test batch to run in a single '
                      'process.')
  # --test-launcher-filter-file is specified relative to --output-directory,
  # so specifying type=os.path.* will break it.
  parser.add_argument('--test-launcher-filter-file',
                      help='Pass filter file through to target process.')
  parser.add_argument('--test-launcher-jobs',
                      type=int,
                      help='Sets the number of parallel test jobs.')
  parser.add_argument('--test_launcher_summary_output',
                      help='Currently ignored for 2-sided roll.')
  parser.add_argument('child_args', nargs='*',
                      help='Arguments for the test process.')
  parser.add_argument('-d', '--device', action='store_true', default=False,
                      help='Run on hardware device instead of QEMU.')
  args = parser.parse_args()

  child_args = ['--test-launcher-retry-limit=0']

  if int(os.environ.get('CHROME_HEADLESS', 0)) != 0:
    # When running on bots (without KVM) execution is quite slow. The test
    # launcher times out a subprocess after 45s which can be too short. Make the
    # timeout twice as long.
    child_args.append('--test-launcher-timeout=90000')

  if args.single_process_tests:
    child_args.append('--single-process-tests')

  if args.test_launcher_batch_limit:
    child_args.append('--test-launcher-batch-limit=%d' %
                       args.test_launcher_batch_limit)
  if args.test_launcher_jobs:
    child_args.append('--test-launcher-jobs=%d' %
                       args.test_launcher_jobs)
  if args.gtest_filter:
    child_args.append('--gtest_filter=' + args.gtest_filter)
  if args.gtest_repeat:
    child_args.append('--gtest_repeat=' + args.gtest_repeat)
  if args.child_args:
    child_args.extend(args.child_args)

  bootfs = BuildBootfs(args.output_directory, args.runtime_deps_path,
                       args.test_name, child_args,
                       args.test_launcher_filter_file, args.device,
                       args.dry_run)

  kernel_path = os.path.join(SDK_ROOT, 'kernel', 'magenta.bin')

  if args.device:
    # TODO(fuchsia): This doesn't capture stdout as there's no way to do so
    # currently. See https://crbug.com/749242.
    bootserver_path = os.path.join(SDK_ROOT, 'tools', 'bootserver')
    bootserver_command = [bootserver_path, '-1', kernel_path, bootfs]
    RunAndCheck(args.dry_run, bootserver_command)
  else:
    qemu_path = os.path.join(SDK_ROOT, 'qemu', 'bin', 'qemu-system-x86_64')

    qemu_command = [qemu_path,
        '-m', '2048',
        '-nographic',
        '-net', 'none',
        '-smp', '4',
        '-machine', 'q35',
        '-kernel', kernel_path,
        '-initrd', bootfs,

        # Use stdio for the guest OS only; don't attach the QEMU interactive
        # monitor.
        '-serial', 'stdio',
        '-monitor', 'none',

        # TERM=dumb tells the guest OS to not emit ANSI commands that trigger
        # noisy ANSI spew from the user's terminal emulator.
        '-append', 'TERM=dumb kernel.halt_on_panic=true']
    if int(os.environ.get('CHROME_HEADLESS', 0)) == 0:
      qemu_command += ['-enable-kvm', '-cpu', 'host,migratable=no']
    else:
      qemu_command += ['-cpu', 'Haswell,+smap,-check']

    if args.dry_run:
      print 'Run:', qemu_command
    else:
      prefix = r'^.*> '
      bt_with_offset_re = re.compile(prefix +
          'bt#(\d+): pc 0x[0-9a-f]+ sp (0x[0-9a-f]+) \((\S+),(0x[0-9a-f]+)\)$')
      bt_end_re = re.compile(prefix + 'bt#(\d+): end')

      # We pass a separate stdin stream to qemu. Sharing stdin across processes
      # leads to flakiness due to the OS prematurely killing the stream and the
      # Python script panicking and aborting.
      # The precise root cause is still nebulous, but this fix works.
      # See crbug.com/741194 .
      qemu_popen = subprocess.Popen(
          qemu_command, stdout=subprocess.PIPE, stdin=open(os.devnull))

      # A buffer of backtrace entries awaiting symbolization, stored as tuples.
      # Element #0: backtrace frame number (starting at 0).
      # Element #1: path to executable code corresponding to the current frame.
      # Element #2: memory offset within the executable.
      bt_entries = []

      success = False
      while True:
        line = qemu_popen.stdout.readline()
        if not line:
          break
        print line,
        if 'SUCCESS: all tests passed.' in line:
          success = True
        if bt_end_re.match(line.strip()):
          if bt_entries:
            print '----- start symbolized stack'
            for processed in ParallelSymbolizeBacktrace(bt_entries):
              print processed
            print '----- end symbolized stack'
          bt_entries = []
        else:
          m = bt_with_offset_re.match(line.strip())
          if m:
            bt_entries.append((m.group(1), args.test_name, m.group(4)))
      qemu_popen.wait()

      return 0 if success else 1

  return 0


if __name__ == '__main__':
  sys.exit(main())

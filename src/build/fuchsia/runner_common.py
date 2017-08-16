#!/usr/bin/env python
#
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Packages a user.bootfs for a Fuchsia boot image, pulling in the runtime
dependencies of a  binary, and then uses either QEMU from the Fuchsia SDK
to run, or starts the bootserver to allow running on a hardware device."""

import argparse
import multiprocessing
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile


DIR_SOURCE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
SDK_ROOT = os.path.join(DIR_SOURCE_ROOT, 'third_party', 'fuchsia-sdk')
SYMBOLIZATION_TIMEOUT_SECS = 10


def _RunAndCheck(dry_run, args):
  if dry_run:
    print 'Run:', ' '.join(args)
    return 0
  else:
    try:
      subprocess.check_call(args)
      return 0
    except subprocess.CalledProcessError as e:
      return e.returncode


def _DumpFile(dry_run, name, description):
  """Prints out the contents of |name| if |dry_run|."""
  if not dry_run:
    return
  print
  print 'Contents of %s (for %s)' % (name, description)
  print '-' * 80
  with open(name) as f:
    sys.stdout.write(f.read())
  print '-' * 80


def _MakeTargetImageName(common_prefix, output_directory, location):
  """Generates the relative path name to be used in the file system image.
  common_prefix: a prefix of both output_directory and location that
                 be removed.
  output_directory: an optional prefix on location that will also be removed.
  location: the file path to relativize.

  .so files will be stored into the lib subdirectory to be able to be found by
  default by the loader.

  Examples:

  >>> _MakeTargetImageName(common_prefix='/work/cr/src',
  ...                      output_directory='/work/cr/src/out/fuch',
  ...                      location='/work/cr/src/base/test/data/xyz.json')
  'base/test/data/xyz.json'

  >>> _MakeTargetImageName(common_prefix='/work/cr/src',
  ...                      output_directory='/work/cr/src/out/fuch',
  ...                      location='/work/cr/src/out/fuch/icudtl.dat')
  'icudtl.dat'

  >>> _MakeTargetImageName(common_prefix='/work/cr/src',
  ...                      output_directory='/work/cr/src/out/fuch',
  ...                      location='/work/cr/src/out/fuch/libbase.so')
  'lib/libbase.so'
  """
  if not common_prefix.endswith(os.sep):
    common_prefix += os.sep
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


def _ExpandDirectories(file_mapping, mapper):
  """Walks directories listed in |file_mapping| and adds their contents to
  |file_mapping|, using |mapper| to determine the target filename.
  """
  expanded = {}
  for target, source in file_mapping.items():
    if os.path.isdir(source):
      files = [os.path.join(dir_path, filename)
               for dir_path, dir_names, file_names in os.walk(source)
               for filename in file_names]
      for f in files:
        expanded[mapper(f)] = f
    elif os.path.exists(source):
      expanded[target] = source
    else:
      raise Exception('%s does not exist' % source)
  return expanded


def _StripBinary(dry_run, bin_path):
  """Creates a stripped copy of the executable at |bin_path| and returns the
  path to the stripped copy."""
  strip_path = tempfile.mktemp()
  _RunAndCheck(dry_run, ['/usr/bin/strip', bin_path, '-o', strip_path])
  if not dry_run and not os.path.exists(strip_path):
    raise Exception('strip did not create output file')
  return strip_path


def _StripBinaries(dry_run, file_mapping):
  """Strips all executables in |file_mapping|, and returns a new mapping
  dictionary, suitable to pass to _WriteManifest()"""
  new_mapping = file_mapping.copy()
  for target, source in file_mapping.iteritems():
    with open(source, 'rb') as f:
      file_tag = f.read(4)
    if file_tag == '\x7fELF':
      new_mapping[target] = _StripBinary(dry_run, source)
  return new_mapping


def _WriteManifest(manifest_file, file_mapping):
  """Writes |file_mapping| to the given |manifest_file| (a file object) in a
  form suitable for consumption by mkbootfs."""
  for target, source in file_mapping.viewitems():
    manifest_file.write('%s=%s\n' % (target, source))


def ReadRuntimeDeps(deps_path, output_directory):
  result = []
  for f in open(deps_path):
    abs_path = os.path.abspath(os.path.join(output_directory, f.strip()));
    target_path = \
        _MakeTargetImageName(DIR_SOURCE_ROOT, output_directory, abs_path)
    result.append((target_path, abs_path))
  return result

def BuildBootfs(output_directory, runtime_deps, bin_name, child_args,
                dry_run, power_off):
  # |runtime_deps| already contains (target, source) pairs for the runtime deps,
  # so we can initialize |file_mapping| from it directly.
  file_mapping = dict(runtime_deps)

  # Generate a script that runs the binaries and shuts down QEMU (if used).
  autorun_file = tempfile.NamedTemporaryFile()
  autorun_file.write('#!/bin/sh\n')
  if int(os.environ.get('CHROME_HEADLESS', 0)) != 0:
    autorun_file.write('export CHROME_HEADLESS=1\n')
  autorun_file.write('echo Executing ' + os.path.basename(bin_name) + ' ' +
                     ' '.join(child_args) + '\n')
  autorun_file.write('/system/' + os.path.basename(bin_name))
  for arg in child_args:
    autorun_file.write(' "%s"' % arg);
  autorun_file.write('\n')
  autorun_file.write('echo Process terminated.\n')

  if power_off:
    # If shutdown of QEMU happens too soon after the program finishes, log
    # statements from the end of the run will be lost, so sleep for a bit before
    # shutting down. When running on device don't power off so the output and
    # system can be inspected.
    autorun_file.write('msleep 3000\n')
    autorun_file.write('dm poweroff\n')

  autorun_file.flush()
  os.chmod(autorun_file.name, 0750)
  _DumpFile(dry_run, autorun_file.name, 'autorun')

  # Add the autorun file and target binary to |file_mapping|.
  file_mapping['autorun'] = autorun_file.name
  file_mapping[os.path.basename(bin_name)] = bin_name

  # Find the full list of files to add to the bootfs.
  file_mapping = _ExpandDirectories(
      file_mapping,
      lambda x: _MakeTargetImageName(DIR_SOURCE_ROOT, output_directory, x))

  # Strip any binaries in the file list, and generate a manifest mapping.
  manifest_mapping = _StripBinaries(dry_run, file_mapping)

  # Write the target, source mappings to a file suitable for bootfs.
  manifest_file = tempfile.NamedTemporaryFile()
  _WriteManifest(manifest_file.file, manifest_mapping)
  manifest_file.flush()
  _DumpFile(dry_run, manifest_file.name, 'manifest')

  # Run mkbootfs with the manifest to copy the necessary files into the bootfs.
  mkbootfs_path = os.path.join(SDK_ROOT, 'tools', 'mkbootfs')
  bootfs_name = bin_name + '.bootfs'
  if _RunAndCheck(
      dry_run,
      [mkbootfs_path, '-o', bootfs_name,
       '--target=boot', os.path.join(SDK_ROOT, 'bootdata.bin'),
       '--target=system', manifest_file.name]) != 0:
    return None

  # Return both the name of the bootfs file, and the filename mapping.
  return (bootfs_name, file_mapping)


def _SymbolizeEntry(entry):
  filename_re = re.compile(r'at ([-._a-zA-Z0-9/+]+):(\d+)')
  raw, frame_id = entry['raw'], entry['frame_id']
  prefix = '#%s: ' % frame_id
  if entry.has_key('debug_binary') and entry.has_key('pc_offset'):
    # Invoke addr2line on the host-side binary to resolve the symbol.
    addr2line_output = subprocess.check_output(
        ['addr2line', '-Cipf', '--exe=' + entry['debug_binary'],
         entry['pc_offset']])

    # addr2line outputs a second line for inlining information, offset
    # that to align it properly after the frame index.
    addr2line_filtered = addr2line_output.strip().replace(
        '(inlined', ' ' * len(prefix) + '(inlined')

    # Relativize path to DIR_SOURCE_ROOT if we see a filename.
    def RelativizePath(m):
      relpath = os.path.relpath(os.path.normpath(m.group(1)), DIR_SOURCE_ROOT)
      return 'at ' + relpath + ':' + m.group(2)
    addr2line_filtered = filename_re.sub(RelativizePath, addr2line_filtered)

    # If symbolization fails just output the raw backtrace.
    if '??' in addr2line_filtered:
      addr2line_filtered = raw
  else:
    addr2line_filtered = raw

  return '%s%s' % (prefix, addr2line_filtered)


def _FindDebugBinary(entry, file_mapping):
  """Looks up the binary listed in |entry| in the |file_mapping|, and returns
  the corresponding host-side binary's filename, or None."""
  binary = entry['binary']
  if not binary:
    return None

  app_prefix = 'app:'
  if binary.startswith(app_prefix):
    binary = binary[len(app_prefix):]

  # Names in |file_mapping| are all relative to "/system/".
  path_prefix = '/system/'
  if not binary.startswith(path_prefix):
    return None
  binary = binary[len(path_prefix):]

  if binary in file_mapping:
    return file_mapping[binary]

  # |binary| may be truncated by the crashlogger, so if there is a unique
  # match for the truncated name in |file_mapping|, use that instead.
  matches = filter(lambda x: x.startswith(binary), file_mapping.keys())
  if len(matches) == 1:
    return file_mapping[matches[0]]

  return None

def _ParallelSymbolizeBacktrace(backtrace, file_mapping):
  # Disable handling of SIGINT during sub-process creation, to prevent
  # sub-processes from consuming Ctrl-C signals, rather than the parent
  # process doing so.
  saved_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
  p = multiprocessing.Pool(multiprocessing.cpu_count())

  # Restore the signal handler for the parent process.
  signal.signal(signal.SIGINT, saved_sigint_handler)

  # Resolve the |binary| name in each entry to a host-accessible filename.
  for entry in backtrace:
    debug_binary = _FindDebugBinary(entry, file_mapping)
    if debug_binary:
      entry['debug_binary'] = debug_binary

  symbolized = []
  try:
    result = p.map_async(_SymbolizeEntry, backtrace)
    symbolized = result.get(SYMBOLIZATION_TIMEOUT_SECS)
    if not symbolized:
      return []
  except multiprocessing.TimeoutError:
    return ['(timeout error occurred during symbolization)']
  except KeyboardInterrupt:  # SIGINT
    p.terminate()

  return symbolized


def RunFuchsia(bootfs_and_manifest, use_device, dry_run, interactive):
  bootfs, bootfs_manifest = bootfs_and_manifest
  kernel_path = os.path.join(SDK_ROOT, 'kernel', 'magenta.bin')

  if use_device:
    # TODO(fuchsia): This doesn't capture stdout as there's no way to do so
    # currently. See https://crbug.com/749242.
    bootserver_path = os.path.join(SDK_ROOT, 'tools', 'bootserver')
    bootserver_command = [bootserver_path, '-1', kernel_path, bootfs]
    return _RunAndCheck(dry_run, bootserver_command)

  qemu_path = os.path.join(SDK_ROOT, 'qemu', 'bin', 'qemu-system-x86_64')
  qemu_command = [qemu_path,
      '-m', '2048',
      '-nographic',
      '-smp', '4',
      '-machine', 'q35',
      '-kernel', kernel_path,
      '-initrd', bootfs,

      # Configure virtual network. The guest will get 192.168.3.9 from
      # DHCP, while the host will be accessible as 192.168.3.2 . The network
      # is used in the tests to connect to testserver running on the host.
      '-netdev', 'user,id=net0,net=192.168.3.0/24,dhcpstart=192.168.3.9,' +
                 'host=192.168.3.2',
      '-device', 'e1000,netdev=net0',
      ]

  if interactive:
    # TERM is passed through to make locally entered commands echo. With
    # TERM=dumb what's typed isn't visible.
    qemu_command.extend([
      '-append', 'TERM=%s kernel.halt_on_panic=true' % os.environ.get('TERM'),
    ])
  else:
    qemu_command.extend([
      # Use stdio for the guest OS only; don't attach the QEMU interactive
      # monitor.
      '-serial', 'stdio',
      '-monitor', 'none',

      # TERM=dumb tells the guest OS to not emit ANSI commands that trigger
      # noisy ANSI spew from the user's terminal emulator.
      '-append', 'TERM=dumb kernel.halt_on_panic=true',
    ])

  if int(os.environ.get('CHROME_HEADLESS', 0)) == 0:
    qemu_command += ['-enable-kvm', '-cpu', 'host,migratable=no']
  else:
    qemu_command += ['-cpu', 'Haswell,+smap,-check']

  if dry_run:
    print 'Run:', ' '.join(qemu_command)
    return 0

  if interactive:
    subprocess.check_call(qemu_command)
    return 0

  # Set up backtrace-parsing regexps.
  qemu_prefix = re.compile(r'^.*> ')
  backtrace_prefix = re.compile(r'bt#(?P<frame_id>\d+): ')

  # Back-trace line matcher/parser assumes that 'pc' is always present, and
  # expects that 'sp' and ('binary','pc_offset') may also be provided.
  backtrace_entry = re.compile(
      r'pc 0(?:x[0-9a-f]+)? ' +
      r'(?:sp 0x[0-9a-f]+ )?' +
      r'(?:\((?P<binary>\S+),(?P<pc_offset>0x[0-9a-f]+)\))?$')

  # We pass a separate stdin stream to qemu. Sharing stdin across processes
  # leads to flakiness due to the OS prematurely killing the stream and the
  # Python script panicking and aborting.
  # The precise root cause is still nebulous, but this fix works.
  # See crbug.com/741194.
  qemu_popen = subprocess.Popen(
      qemu_command, stdout=subprocess.PIPE, stdin=open(os.devnull))

  # A buffer of backtrace entries awaiting symbolization, stored as dicts:
  # raw: The original back-trace line that followed the prefix.
  # frame_id: backtrace frame number (starting at 0).
  # binary: path to executable code corresponding to the current frame.
  # pc_offset: memory offset within the executable.
  backtrace_entries = []

  success = False
  while True:
    line = qemu_popen.stdout.readline().strip()
    if not line:
      break
    if 'SUCCESS: all tests passed.' in line:
      success = True

    # If the line is not from QEMU then don't try to process it.
    matched = qemu_prefix.match(line)
    if not matched:
      print line
      continue
    guest_line = line[matched.end():]

    # Look for the back-trace prefix, otherwise just print the line.
    matched = backtrace_prefix.match(guest_line)
    if not matched:
      print line
      continue
    backtrace_line = guest_line[matched.end():]

    # If this was the end of a back-trace then symbolize and print it.
    frame_id = matched.group('frame_id')
    if backtrace_line == 'end':
      if backtrace_entries:
        for processed in _ParallelSymbolizeBacktrace(backtrace_entries,
                                                     bootfs_manifest):
          print processed
      backtrace_entries = []
      continue

    # Otherwise, parse the program-counter offset, etc into |backtrace_entries|.
    matched = backtrace_entry.match(backtrace_line)
    if matched:
      # |binary| and |pc_offset| will be None if not present.
      backtrace_entries.append(
          {'raw': backtrace_line, 'frame_id': frame_id,
           'binary': matched.group('binary'),
           'pc_offset': matched.group('pc_offset')})
    else:
      backtrace_entries.append(
          {'raw': backtrace_line, 'frame_id': frame_id,
           'binary': None, 'pc_offset': None})

  qemu_popen.wait()

  return 0 if success else 1

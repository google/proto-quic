#!/usr/bin/env python
# Copyright 2012 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Runs a command with optional isolated input/output.

Despite name "run_isolated", can run a generic non-isolated command specified as
args.

If input isolated hash is provided, fetches it, creates a tree of hard links,
appends args to the command in the fetched isolated and runs it.
To improve performance, keeps a local cache.
The local cache can safely be deleted.

Any ${EXECUTABLE_SUFFIX} on the command line will be replaced with ".exe" string
on Windows and "" on other platforms.

Any ${ISOLATED_OUTDIR} on the command line will be replaced by the location of a
temporary directory upon execution of the command specified in the .isolated
file. All content written to this directory will be uploaded upon termination
and the .isolated file describing this directory will be printed to stdout.

Any ${SWARMING_BOT_FILE} on the command line will be replaced by the value of
the --bot-file parameter. This file is used by a swarming bot to communicate
state of the host to tasks. It is written to by the swarming bot's
on_before_task() hook in the swarming server's custom bot_config.py.
"""

__version__ = '0.9.1'

import argparse
import base64
import collections
import contextlib
import json
import logging
import optparse
import os
import sys
import tempfile
import time

from third_party.depot_tools import fix_encoding

from utils import file_path
from utils import fs
from utils import large
from utils import logging_utils
from utils import on_error
from utils import subprocess42
from utils import tools
from utils import zip_package

import auth
import cipd
import isolateserver
import named_cache


# Absolute path to this file (can be None if running from zip on Mac).
THIS_FILE_PATH = os.path.abspath(
    __file__.decode(sys.getfilesystemencoding())) if __file__ else None

# Directory that contains this file (might be inside zip package).
BASE_DIR = os.path.dirname(THIS_FILE_PATH) if __file__.decode(
    sys.getfilesystemencoding()) else None

# Directory that contains currently running script file.
if zip_package.get_main_script_path():
  MAIN_DIR = os.path.dirname(
      os.path.abspath(zip_package.get_main_script_path()))
else:
  # This happens when 'import run_isolated' is executed at the python
  # interactive prompt, in that case __file__ is undefined.
  MAIN_DIR = None


# Magic variables that can be found in the isolate task command line.
ISOLATED_OUTDIR_PARAMETER = '${ISOLATED_OUTDIR}'
EXECUTABLE_SUFFIX_PARAMETER = '${EXECUTABLE_SUFFIX}'
SWARMING_BOT_FILE_PARAMETER = '${SWARMING_BOT_FILE}'


# The name of the log file to use.
RUN_ISOLATED_LOG_FILE = 'run_isolated.log'


# The name of the log to use for the run_test_cases.py command
RUN_TEST_CASES_LOG = 'run_test_cases.log'


# Use short names for temporary directories. This is driven by Windows, which
# imposes a relatively short maximum path length of 260 characters, often
# referred to as MAX_PATH. It is relatively easy to create files with longer
# path length. A use case is with recursive depedency treesV like npm packages.
#
# It is recommended to start the script with a `root_dir` as short as
# possible.
# - ir stands for isolated_run
# - io stands for isolated_out
# - it stands for isolated_tmp
ISOLATED_RUN_DIR = u'ir'
ISOLATED_OUT_DIR = u'io'
ISOLATED_TMP_DIR = u'it'


def get_as_zip_package(executable=True):
  """Returns ZipPackage with this module and all its dependencies.

  If |executable| is True will store run_isolated.py as __main__.py so that
  zip package is directly executable be python.
  """
  # Building a zip package when running from another zip package is
  # unsupported and probably unneeded.
  assert not zip_package.is_zipped_module(sys.modules[__name__])
  assert THIS_FILE_PATH
  assert BASE_DIR
  package = zip_package.ZipPackage(root=BASE_DIR)
  package.add_python_file(THIS_FILE_PATH, '__main__.py' if executable else None)
  package.add_python_file(os.path.join(BASE_DIR, 'isolate_storage.py'))
  package.add_python_file(os.path.join(BASE_DIR, 'isolated_format.py'))
  package.add_python_file(os.path.join(BASE_DIR, 'isolateserver.py'))
  package.add_python_file(os.path.join(BASE_DIR, 'auth.py'))
  package.add_python_file(os.path.join(BASE_DIR, 'cipd.py'))
  package.add_python_file(os.path.join(BASE_DIR, 'named_cache.py'))
  package.add_directory(os.path.join(BASE_DIR, 'libs'))
  package.add_directory(os.path.join(BASE_DIR, 'third_party'))
  package.add_directory(os.path.join(BASE_DIR, 'utils'))
  return package


def make_temp_dir(prefix, root_dir):
  """Returns a new unique temporary directory."""
  return unicode(tempfile.mkdtemp(prefix=prefix, dir=root_dir))


def change_tree_read_only(rootdir, read_only):
  """Changes the tree read-only bits according to the read_only specification.

  The flag can be 0, 1 or 2, which will affect the possibility to modify files
  and create or delete files.
  """
  if read_only == 2:
    # Files and directories (except on Windows) are marked read only. This
    # inhibits modifying, creating or deleting files in the test directory,
    # except on Windows where creating and deleting files is still possible.
    file_path.make_tree_read_only(rootdir)
  elif read_only == 1:
    # Files are marked read only but not the directories. This inhibits
    # modifying files but creating or deleting files is still possible.
    file_path.make_tree_files_read_only(rootdir)
  elif read_only in (0, None):
    # Anything can be modified.
    # TODO(maruel): This is currently dangerous as long as DiskCache.touch()
    # is not yet changed to verify the hash of the content of the files it is
    # looking at, so that if a test modifies an input file, the file must be
    # deleted.
    file_path.make_tree_writeable(rootdir)
  else:
    raise ValueError(
        'change_tree_read_only(%s, %s): Unknown flag %s' %
        (rootdir, read_only, read_only))


def process_command(command, out_dir, bot_file):
  """Replaces variables in a command line.

  Raises:
    ValueError if a parameter is requested in |command| but its value is not
      provided.
  """
  def fix(arg):
    arg = arg.replace(EXECUTABLE_SUFFIX_PARAMETER, cipd.EXECUTABLE_SUFFIX)
    replace_slash = False
    if ISOLATED_OUTDIR_PARAMETER in arg:
      if not out_dir:
        raise ValueError(
            'output directory is requested in command, but not provided; '
            'please specify one')
      arg = arg.replace(ISOLATED_OUTDIR_PARAMETER, out_dir)
      replace_slash = True
    if SWARMING_BOT_FILE_PARAMETER in arg:
      if bot_file:
        arg = arg.replace(SWARMING_BOT_FILE_PARAMETER, bot_file)
        replace_slash = True
      else:
        logging.warning('SWARMING_BOT_FILE_PARAMETER found in command, but no '
                        'bot_file specified. Leaving parameter unchanged.')
    if replace_slash:
      # Replace slashes only if parameters are present
      # because of arguments like '${ISOLATED_OUTDIR}/foo/bar'
      arg = arg.replace('/', os.sep)
    return arg

  return [fix(arg) for arg in command]


def get_command_env(tmp_dir, cipd_info):
  """Returns full OS environment to run a command in.

  Sets up TEMP, puts directory with cipd binary in front of PATH, and exposes
  CIPD_CACHE_DIR env var.

  Args:
    tmp_dir: temp directory.
    cipd_info: CipdInfo object is cipd client is used, None if not.
  """
  def to_fs_enc(s):
    if isinstance(s, str):
      return s
    return s.encode(sys.getfilesystemencoding())

  env = os.environ.copy()

  # TMPDIR is specified as the POSIX standard envvar for the temp directory.
  #   * mktemp on linux respects $TMPDIR, not $TMP
  #   * mktemp on OS X SOMETIMES respects $TMPDIR
  #   * chromium's base utils respects $TMPDIR on linux, $TEMP on windows.
  #     Unfortunately at the time of writing it completely ignores all envvars
  #     on OS X.
  #   * python respects TMPDIR, TEMP, and TMP (regardless of platform)
  #   * golang respects TMPDIR on linux+mac, TEMP on windows.
  key = {'win32': 'TEMP'}.get(sys.platform, 'TMPDIR')
  env[key] = to_fs_enc(tmp_dir)

  if cipd_info:
    bin_dir = os.path.dirname(cipd_info.client.binary_path)
    env['PATH'] = '%s%s%s' % (to_fs_enc(bin_dir), os.pathsep, env['PATH'])
    env['CIPD_CACHE_DIR'] = to_fs_enc(cipd_info.cache_dir)

  return env


def run_command(command, cwd, env, hard_timeout, grace_period):
  """Runs the command.

  Returns:
    tuple(process exit code, bool if had a hard timeout)
  """
  logging.info('run_command(%s, %s)' % (command, cwd))

  exit_code = None
  had_hard_timeout = False
  with tools.Profiler('RunTest'):
    proc = None
    had_signal = []
    try:
      # TODO(maruel): This code is imperfect. It doesn't handle well signals
      # during the download phase and there's short windows were things can go
      # wrong.
      def handler(signum, _frame):
        if proc and not had_signal:
          logging.info('Received signal %d', signum)
          had_signal.append(True)
          raise subprocess42.TimeoutExpired(command, None)

      proc = subprocess42.Popen(command, cwd=cwd, env=env, detached=True)
      with subprocess42.set_signal_handler(subprocess42.STOP_SIGNALS, handler):
        try:
          exit_code = proc.wait(hard_timeout or None)
        except subprocess42.TimeoutExpired:
          if not had_signal:
            logging.warning('Hard timeout')
            had_hard_timeout = True
          logging.warning('Sending SIGTERM')
          proc.terminate()

      # Ignore signals in grace period. Forcibly give the grace period to the
      # child process.
      if exit_code is None:
        ignore = lambda *_: None
        with subprocess42.set_signal_handler(subprocess42.STOP_SIGNALS, ignore):
          try:
            exit_code = proc.wait(grace_period or None)
          except subprocess42.TimeoutExpired:
            # Now kill for real. The user can distinguish between the
            # following states:
            # - signal but process exited within grace period,
            #   hard_timed_out will be set but the process exit code will be
            #   script provided.
            # - processed exited late, exit code will be -9 on posix.
            logging.warning('Grace exhausted; sending SIGKILL')
            proc.kill()
      logging.info('Waiting for proces exit')
      exit_code = proc.wait()
    except OSError:
      # This is not considered to be an internal error. The executable simply
      # does not exit.
      sys.stderr.write(
          '<The executable does not exist or a dependent library is missing>\n'
          '<Check for missing .so/.dll in the .isolate or GN file>\n'
          '<Command: %s>\n' % command)
      if os.environ.get('SWARMING_TASK_ID'):
        # Give an additional hint when running as a swarming task.
        sys.stderr.write(
            '<See the task\'s page for commands to help diagnose this issue '
            'by reproducing the task locally>\n')
      exit_code = 1
  logging.info(
      'Command finished with exit code %d (%s)',
      exit_code, hex(0xffffffff & exit_code))
  return exit_code, had_hard_timeout


def fetch_and_map(isolated_hash, storage, cache, outdir, use_symlinks):
  """Fetches an isolated tree, create the tree and returns (bundle, stats)."""
  start = time.time()
  bundle = isolateserver.fetch_isolated(
      isolated_hash=isolated_hash,
      storage=storage,
      cache=cache,
      outdir=outdir,
      use_symlinks=use_symlinks)
  return bundle, {
    'duration': time.time() - start,
    'initial_number_items': cache.initial_number_items,
    'initial_size': cache.initial_size,
    'items_cold': base64.b64encode(large.pack(sorted(cache.added))),
    'items_hot': base64.b64encode(
        large.pack(sorted(set(cache.used) - set(cache.added)))),
  }


def link_outputs_to_outdir(run_dir, out_dir, outputs):
  """Links any named outputs to out_dir so they can be uploaded.

  Raises an error if the file already exists in that directory.
  """
  if not outputs:
    return
  isolateserver.create_directories(out_dir, outputs)
  for o in outputs:
    try:
      file_path.link_file(
          os.path.join(out_dir, o),
          os.path.join(run_dir, o),
          file_path.HARDLINK_WITH_FALLBACK)
    except OSError as e:
      logging.info("Couldn't collect output file %s: %s", o, e)


def delete_and_upload(storage, out_dir, leak_temp_dir):
  """Deletes the temporary run directory and uploads results back.

  Returns:
    tuple(outputs_ref, success, stats)
    - outputs_ref: a dict referring to the results archived back to the isolated
          server, if applicable.
    - success: False if something occurred that means that the task must
          forcibly be considered a failure, e.g. zombie processes were left
          behind.
    - stats: uploading stats.
  """
  # Upload out_dir and generate a .isolated file out of this directory. It is
  # only done if files were written in the directory.
  outputs_ref = None
  cold = []
  hot = []
  start = time.time()

  if fs.isdir(out_dir) and fs.listdir(out_dir):
    with tools.Profiler('ArchiveOutput'):
      try:
        results, f_cold, f_hot = isolateserver.archive_files_to_storage(
            storage, [out_dir], None)
        outputs_ref = {
          'isolated': results[0][0],
          'isolatedserver': storage.location,
          'namespace': storage.namespace,
        }
        cold = sorted(i.size for i in f_cold)
        hot = sorted(i.size for i in f_hot)
      except isolateserver.Aborted:
        # This happens when a signal SIGTERM was received while uploading data.
        # There is 2 causes:
        # - The task was too slow and was about to be killed anyway due to
        #   exceeding the hard timeout.
        # - The amount of data uploaded back is very large and took too much
        #   time to archive.
        sys.stderr.write('Received SIGTERM while uploading')
        # Re-raise, so it will be treated as an internal failure.
        raise

  success = False
  try:
    if (not leak_temp_dir and fs.isdir(out_dir) and
        not file_path.rmtree(out_dir)):
      logging.error('Had difficulties removing out_dir %s', out_dir)
    else:
      success = True
  except OSError as e:
    # When this happens, it means there's a process error.
    logging.exception('Had difficulties removing out_dir %s: %s', out_dir, e)
  stats = {
    'duration': time.time() - start,
    'items_cold': base64.b64encode(large.pack(cold)),
    'items_hot': base64.b64encode(large.pack(hot)),
  }
  return outputs_ref, success, stats


def map_and_run(
    command, isolated_hash, storage, isolate_cache, outputs, init_named_caches,
    leak_temp_dir, root_dir, hard_timeout, grace_period, bot_file,
    install_packages_fn, use_symlinks, constant_run_path):
  """Runs a command with optional isolated input/output.

  See run_tha_test for argument documentation.

  Returns metadata about the result.
  """
  assert isinstance(command, list), command
  assert root_dir or root_dir is None
  result = {
    'duration': None,
    'exit_code': None,
    'had_hard_timeout': False,
    'internal_failure': None,
    'stats': {
    # 'isolated': {
    #    'cipd': {
    #      'duration': 0.,
    #      'get_client_duration': 0.,
    #    },
    #    'download': {
    #      'duration': 0.,
    #      'initial_number_items': 0,
    #      'initial_size': 0,
    #      'items_cold': '<large.pack()>',
    #      'items_hot': '<large.pack()>',
    #    },
    #    'upload': {
    #      'duration': 0.,
    #      'items_cold': '<large.pack()>',
    #      'items_hot': '<large.pack()>',
    #    },
    #  },
    },
    # 'cipd_pins': {
    #   'packages': [
    #     {'package_name': ..., 'version': ..., 'path': ...},
    #     ...
    #   ],
    #  'client_package': {'package_name': ..., 'version': ...},
    # },
    'outputs_ref': None,
    'version': 5,
  }

  if root_dir:
    file_path.ensure_tree(root_dir, 0700)
  elif isolate_cache.cache_dir:
    root_dir = os.path.dirname(isolate_cache.cache_dir)
  # See comment for these constants.
  # If root_dir is not specified, it is not constant.
  # TODO(maruel): This is not obvious. Change this to become an error once we
  # make the constant_run_path an exposed flag.
  if constant_run_path and root_dir:
    run_dir = os.path.join(root_dir, ISOLATED_RUN_DIR)
    os.mkdir(run_dir)
  else:
    run_dir = make_temp_dir(ISOLATED_RUN_DIR, root_dir)
  # storage should be normally set but don't crash if it is not. This can happen
  # as Swarming task can run without an isolate server.
  out_dir = make_temp_dir(ISOLATED_OUT_DIR, root_dir) if storage else None
  tmp_dir = make_temp_dir(ISOLATED_TMP_DIR, root_dir)
  cwd = run_dir

  try:
    with install_packages_fn(run_dir) as cipd_info:
      if cipd_info:
        result['stats']['cipd'] = cipd_info.stats
        result['cipd_pins'] = cipd_info.pins

      if isolated_hash:
        isolated_stats = result['stats'].setdefault('isolated', {})
        bundle, isolated_stats['download'] = fetch_and_map(
            isolated_hash=isolated_hash,
            storage=storage,
            cache=isolate_cache,
            outdir=run_dir,
            use_symlinks=use_symlinks)
        change_tree_read_only(run_dir, bundle.read_only)
        cwd = os.path.normpath(os.path.join(cwd, bundle.relative_cwd))
        # Inject the command
        if bundle.command:
          command = bundle.command + command

      if not command:
        # Handle this as a task failure, not an internal failure.
        sys.stderr.write(
            '<No command was specified!>\n'
            '<Please secify a command when triggering your Swarming task>\n')
        result['exit_code'] = 1
        return result

      # If we have an explicit list of files to return, make sure their
      # directories exist now.
      if storage and outputs:
        isolateserver.create_directories(run_dir, outputs)

      command = tools.fix_python_path(command)
      command = process_command(command, out_dir, bot_file)
      file_path.ensure_command_has_abs_path(command, cwd)

      with init_named_caches(run_dir):
        sys.stdout.flush()
        start = time.time()
        try:
          result['exit_code'], result['had_hard_timeout'] = run_command(
              command, cwd, get_command_env(tmp_dir, cipd_info),
              hard_timeout, grace_period)
        finally:
          result['duration'] = max(time.time() - start, 0)
  except Exception as e:
    # An internal error occurred. Report accordingly so the swarming task will
    # be retried automatically.
    logging.exception('internal failure: %s', e)
    result['internal_failure'] = str(e)
    on_error.report(None)

  # Clean up
  finally:
    try:
      # Try to link files to the output directory, if specified.
      if out_dir:
        link_outputs_to_outdir(run_dir, out_dir, outputs)

      success = False
      if leak_temp_dir:
        success = True
        logging.warning(
            'Deliberately leaking %s for later examination', run_dir)
      else:
        # On Windows rmtree(run_dir) call above has a synchronization effect: it
        # finishes only when all task child processes terminate (since a running
        # process locks *.exe file). Examine out_dir only after that call
        # completes (since child processes may write to out_dir too and we need
        # to wait for them to finish).
        if fs.isdir(run_dir):
          try:
            success = file_path.rmtree(run_dir)
          except OSError as e:
            logging.error('Failure with %s', e)
            success = False
          if not success:
            print >> sys.stderr, (
                'Failed to delete the run directory, thus failing the task.\n'
                'This may be due to a subprocess outliving the main task\n'
                'process, holding on to resources. Please fix the task so\n'
                'that it releases resources and cleans up subprocesses.')
            if result['exit_code'] == 0:
              result['exit_code'] = 1
        if fs.isdir(tmp_dir):
          try:
            success = file_path.rmtree(tmp_dir)
          except OSError as e:
            logging.error('Failure with %s', e)
            success = False
          if not success:
            print >> sys.stderr, (
                'Failed to delete the temp directory, thus failing the task.\n'
                'This may be due to a subprocess outliving the main task\n'
                'process, holding on to resources. Please fix the task so\n'
                'that it releases resources and cleans up subprocesses.')
            if result['exit_code'] == 0:
              result['exit_code'] = 1

      # This deletes out_dir if leak_temp_dir is not set.
      if out_dir:
        isolated_stats = result['stats'].setdefault('isolated', {})
        result['outputs_ref'], success, isolated_stats['upload'] = (
            delete_and_upload(storage, out_dir, leak_temp_dir))
      if not success and result['exit_code'] == 0:
        result['exit_code'] = 1
    except Exception as e:
      # Swallow any exception in the main finally clause.
      if out_dir:
        logging.exception('Leaking out_dir %s: %s', out_dir, e)
      result['internal_failure'] = str(e)
  return result


def run_tha_test(
    command, isolated_hash, storage, isolate_cache, outputs, init_named_caches,
    leak_temp_dir, result_json, root_dir, hard_timeout, grace_period, bot_file,
    install_packages_fn, use_symlinks):
  """Runs an executable and records execution metadata.

  Either command or isolated_hash must be specified.

  If isolated_hash is specified, downloads the dependencies in the cache,
  hardlinks them into a temporary directory and runs the command specified in
  the .isolated.

  A temporary directory is created to hold the output files. The content inside
  this directory will be uploaded back to |storage| packaged as a .isolated
  file.

  Arguments:
    command: a list of string; the command to run OR optional arguments to add
             to the command stated in the .isolated file if a command was
             specified.
    isolated_hash: the SHA-1 of the .isolated file that must be retrieved to
                   recreate the tree of files to run the target executable.
                   The command specified in the .isolated is executed.
                   Mutually exclusive with command argument.
    storage: an isolateserver.Storage object to retrieve remote objects. This
             object has a reference to an isolateserver.StorageApi, which does
             the actual I/O.
    isolate_cache: an isolateserver.LocalCache to keep from retrieving the
                   same objects constantly by caching the objects retrieved.
                   Can be on-disk or in-memory.
    init_named_caches: a function (run_dir) => context manager that creates
                      symlinks for named caches in |run_dir|.
    leak_temp_dir: if true, the temporary directory will be deliberately leaked
                   for later examination.
    result_json: file path to dump result metadata into. If set, the process
                 exit code is always 0 unless an internal error occurred.
    root_dir: path to the directory to use to create the temporary directory. If
              not specified, a random temporary directory is created.
    hard_timeout: kills the process if it lasts more than this amount of
                  seconds.
    grace_period: number of seconds to wait between SIGTERM and SIGKILL.
    install_packages_fn: context manager dir => CipdInfo, see
      install_client_and_packages.
    use_symlinks: create tree with symlinks instead of hardlinks.

  Returns:
    Process exit code that should be used.
  """
  if result_json:
    # Write a json output file right away in case we get killed.
    result = {
      'exit_code': None,
      'had_hard_timeout': False,
      'internal_failure': 'Was terminated before completion',
      'outputs_ref': None,
      'version': 5,
    }
    tools.write_json(result_json, result, dense=True)

  # run_isolated exit code. Depends on if result_json is used or not.
  result = map_and_run(
      command, isolated_hash, storage, isolate_cache, outputs,
      init_named_caches, leak_temp_dir, root_dir, hard_timeout, grace_period,
      bot_file, install_packages_fn, use_symlinks, True)
  logging.info('Result:\n%s', tools.format_json(result, dense=True))

  if result_json:
    # We've found tests to delete 'work' when quitting, causing an exception
    # here. Try to recreate the directory if necessary.
    file_path.ensure_tree(os.path.dirname(result_json))
    tools.write_json(result_json, result, dense=True)
    # Only return 1 if there was an internal error.
    return int(bool(result['internal_failure']))

  # Marshall into old-style inline output.
  if result['outputs_ref']:
    data = {
      'hash': result['outputs_ref']['isolated'],
      'namespace': result['outputs_ref']['namespace'],
      'storage': result['outputs_ref']['isolatedserver'],
    }
    sys.stdout.flush()
    print(
        '[run_isolated_out_hack]%s[/run_isolated_out_hack]' %
        tools.format_json(data, dense=True))
    sys.stdout.flush()
  return result['exit_code'] or int(bool(result['internal_failure']))


# Yielded by 'install_client_and_packages'.
CipdInfo = collections.namedtuple('CipdInfo', [
  'client',     # cipd.CipdClient object
  'cache_dir',  # absolute path to bot-global cipd tag and instance cache
  'stats',      # dict with stats to return to the server
  'pins',       # dict with installed cipd pins to return to the server
])


@contextlib.contextmanager
def noop_install_packages(_run_dir):
  """Placeholder for 'install_client_and_packages' if cipd is disabled."""
  yield None


def _install_packages(run_dir, cipd_cache_dir, client, packages, timeout):
  """Calls 'cipd ensure' for packages.

  Args:
    run_dir (str): root of installation.
    cipd_cache_dir (str): the directory to use for the cipd package cache.
    client (CipdClient): the cipd client to use
    packages: packages to install, list [(path, package_name, version), ...].
    timeout: max duration in seconds that this function can take.

  Returns: list of pinned packages.  Looks like [
    {
      'path': 'subdirectory',
      'package_name': 'resolved/package/name',
      'version': 'deadbeef...',
    },
    ...
  ]
  """
  package_pins = [None]*len(packages)
  def insert_pin(path, name, version, idx):
    package_pins[idx] = {
      'package_name': name,
      # swarming deals with 'root' as '.'
      'path': path or '.',
      'version': version,
    }

  by_path = collections.defaultdict(list)
  for i, (path, name, version) in enumerate(packages):
    # cipd deals with 'root' as ''
    if path == '.':
      path = ''
    by_path[path].append((name, version, i))

  pins = client.ensure(
    run_dir,
    {
      subdir: [(name, vers) for name, vers, _ in pkgs]
      for subdir, pkgs in by_path.iteritems()
    },
    cache_dir=cipd_cache_dir,
    timeout=timeout,
  )

  for subdir, pin_list in sorted(pins.iteritems()):
    this_subdir = by_path[subdir]
    for i, (name, version) in enumerate(pin_list):
      insert_pin(subdir, name, version, this_subdir[i][2])

  assert None not in package_pins

  return package_pins


@contextlib.contextmanager
def install_client_and_packages(
    run_dir, packages, service_url, client_package_name,
    client_version, cache_dir, timeout=None):
  """Bootstraps CIPD client and installs CIPD packages.

  Yields CipdClient, stats, client info and pins (as single CipdInfo object).

  Pins and the CIPD client info are in the form of:
    [
      {
        "path": path, "package_name": package_name, "version": version,
      },
      ...
    ]
  (the CIPD client info is a single dictionary instead of a list)

  such that they correspond 1:1 to all input package arguments from the command
  line. These dictionaries make their all the way back to swarming, where they
  become the arguments of CipdPackage.

  If 'packages' list is empty, will bootstrap CIPD client, but won't install
  any packages.

  The bootstrapped client (regardless whether 'packages' list is empty or not),
  will be made available to the task via $PATH.

  Args:
    run_dir (str): root of installation.
    packages: packages to install, list [(path, package_name, version), ...].
    service_url (str): CIPD server url, e.g.
      "https://chrome-infra-packages.appspot.com."
    client_package_name (str): CIPD package name of CIPD client.
    client_version (str): Version of CIPD client.
    cache_dir (str): where to keep cache of cipd clients, packages and tags.
    timeout: max duration in seconds that this function can take.
  """
  assert cache_dir

  timeoutfn = tools.sliding_timeout(timeout)
  start = time.time()

  cache_dir = os.path.abspath(cache_dir)
  cipd_cache_dir = os.path.join(cache_dir, 'cache')  # tag and instance caches
  run_dir = os.path.abspath(run_dir)
  packages = packages or []

  get_client_start = time.time()
  client_manager = cipd.get_client(
      service_url, client_package_name, client_version, cache_dir,
      timeout=timeoutfn())

  with client_manager as client:
    get_client_duration = time.time() - get_client_start

    package_pins = []
    if packages:
      package_pins = _install_packages(
        run_dir, cipd_cache_dir, client, packages, timeoutfn())

    file_path.make_tree_files_read_only(run_dir)

    total_duration = time.time() - start
    logging.info(
        'Installing CIPD client and packages took %d seconds', total_duration)

    yield CipdInfo(
      client=client,
      cache_dir=cipd_cache_dir,
      stats={
        'duration': total_duration,
        'get_client_duration': get_client_duration,
      },
      pins={
        'client_package': {
          'package_name': client.package_name,
          'version': client.instance_id,
        },
        'packages': package_pins,
      })


def clean_caches(options, isolate_cache, named_cache_manager):
  """Trims isolated and named caches.

  The goal here is to coherently trim both caches, deleting older items
  independent of which container they belong to.
  """
  # TODO(maruel): Trim CIPD cache the same way.
  total = 0
  with named_cache_manager.open():
    oldest_isolated = isolate_cache.get_oldest()
    oldest_named = named_cache_manager.get_oldest()
    trimmers = [
      (
        isolate_cache.trim,
        isolate_cache.get_timestamp(oldest_isolated) if oldest_isolated else 0,
      ),
      (
        lambda: named_cache_manager.trim(options.min_free_space),
        named_cache_manager.get_timestamp(oldest_named) if oldest_named else 0,
      ),
    ]
    trimmers.sort(key=lambda (_, ts): ts)
    # TODO(maruel): This is incorrect, we want to trim 'items' that are strictly
    # the oldest independent of in which cache they live in. Right now, the
    # cache with the oldest item pays the price.
    for trim, _ in trimmers:
      total += trim()
  isolate_cache.cleanup()
  return total


def create_option_parser():
  parser = logging_utils.OptionParserWithLogging(
      usage='%prog <options> [command to run or extra args]',
      version=__version__,
      log_file=RUN_ISOLATED_LOG_FILE)
  parser.add_option(
      '--clean', action='store_true',
      help='Cleans the cache, trimming it necessary and remove corrupted items '
           'and returns without executing anything; use with -v to know what '
           'was done')
  parser.add_option(
      '--no-clean', action='store_true',
      help='Do not clean the cache automatically on startup. This is meant for '
           'bots where a separate execution with --clean was done earlier so '
           'doing it again is redundant')
  parser.add_option(
      '--use-symlinks', action='store_true',
      help='Use symlinks instead of hardlinks')
  parser.add_option(
      '--json',
      help='dump output metadata to json file. When used, run_isolated returns '
           'non-zero only on internal failure')
  parser.add_option(
      '--hard-timeout', type='float', help='Enforce hard timeout in execution')
  parser.add_option(
      '--grace-period', type='float',
      help='Grace period between SIGTERM and SIGKILL')
  parser.add_option(
      '--bot-file',
      help='Path to a file describing the state of the host. The content is '
           'defined by on_before_task() in bot_config.')
  parser.add_option(
      '--output', action='append',
      help='Specifies an output to return. If no outputs are specified, all '
           'files located in $(ISOLATED_OUTDIR) will be returned; '
           'otherwise, outputs in both $(ISOLATED_OUTDIR) and those '
           'specified by --output option (there can be multiple) will be '
           'returned. Note that if a file in OUT_DIR has the same path '
           'as an --output option, the --output version will be returned.')
  parser.add_option(
      '-a', '--argsfile',
      # This is actually handled in parse_args; it's included here purely so it
      # can make it into the help text.
      help='Specify a file containing a JSON array of arguments to this '
           'script. If --argsfile is provided, no other argument may be '
           'provided on the command line.')
  data_group = optparse.OptionGroup(parser, 'Data source')
  data_group.add_option(
      '-s', '--isolated',
      help='Hash of the .isolated to grab from the isolate server.')
  isolateserver.add_isolate_server_options(data_group)
  parser.add_option_group(data_group)

  isolateserver.add_cache_options(parser)

  cipd.add_cipd_options(parser)
  named_cache.add_named_cache_options(parser)

  debug_group = optparse.OptionGroup(parser, 'Debugging')
  debug_group.add_option(
      '--leak-temp-dir',
      action='store_true',
      help='Deliberately leak isolate\'s temp dir for later examination. '
           'Default: %default')
  debug_group.add_option(
      '--root-dir', help='Use a directory instead of a random one')
  parser.add_option_group(debug_group)

  auth.add_auth_options(parser)

  parser.set_defaults(
      cache='cache',
      cipd_cache='cipd_cache',
      named_cache_root='named_caches')
  return parser


def parse_args(args):
  # Create a fake mini-parser just to get out the "-a" command. Note that
  # it's not documented here; instead, it's documented in create_option_parser
  # even though that parser will never actually get to parse it. This is
  # because --argsfile is exclusive with all other options and arguments.
  file_argparse = argparse.ArgumentParser(add_help=False)
  file_argparse.add_argument('-a', '--argsfile')
  (file_args, nonfile_args) = file_argparse.parse_known_args(args)
  if file_args.argsfile:
    if nonfile_args:
      file_argparse.error('Can\'t specify --argsfile with'
                          'any other arguments (%s)' % nonfile_args)
    try:
      with open(file_args.argsfile, 'r') as f:
        args = json.load(f)
    except (IOError, OSError, ValueError) as e:
      # We don't need to error out here - "args" is now empty,
      # so the call below to parser.parse_args(args) will fail
      # and print the full help text.
      print >> sys.stderr, 'Couldn\'t read arguments: %s' % e

  # Even if we failed to read the args, just call the normal parser now since it
  # will print the correct help message.
  parser = create_option_parser()
  options, args = parser.parse_args(args)
  return (parser, options, args)


def main(args):
  (parser, options, args) = parse_args(args)

  isolate_cache = isolateserver.process_cache_options(options, trim=False)
  named_cache_manager = named_cache.process_named_cache_options(parser, options)
  if options.clean:
    if options.isolated:
      parser.error('Can\'t use --isolated with --clean.')
    if options.isolate_server:
      parser.error('Can\'t use --isolate-server with --clean.')
    if options.json:
      parser.error('Can\'t use --json with --clean.')
    if options.named_caches:
      parser.error('Can\t use --named-cache with --clean.')
    clean_caches(options, isolate_cache, named_cache_manager)
    return 0

  if not options.no_clean:
    clean_caches(options, isolate_cache, named_cache_manager)

  if not options.isolated and not args:
    parser.error('--isolated or command to run is required.')

  auth.process_auth_options(parser, options)

  isolateserver.process_isolate_server_options(
    parser, options, True, False)
  if not options.isolate_server:
    if options.isolated:
      parser.error('--isolated requires --isolate-server')
    if ISOLATED_OUTDIR_PARAMETER in args:
      parser.error(
        '%s in args requires --isolate-server' % ISOLATED_OUTDIR_PARAMETER)

  if options.root_dir:
    options.root_dir = unicode(os.path.abspath(options.root_dir))
  if options.json:
    options.json = unicode(os.path.abspath(options.json))

  cipd.validate_cipd_options(parser, options)

  install_packages_fn = noop_install_packages
  if options.cipd_enabled:
    install_packages_fn = lambda run_dir: install_client_and_packages(
        run_dir, cipd.parse_package_args(options.cipd_packages),
        options.cipd_server, options.cipd_client_package,
        options.cipd_client_version, cache_dir=options.cipd_cache)

  @contextlib.contextmanager
  def init_named_caches(run_dir):
    # WARNING: this function depends on "options" variable defined in the outer
    # function.
    with named_cache_manager.open():
      named_cache_manager.create_symlinks(run_dir, options.named_caches)
    try:
      yield
    finally:
      if not options.leak_temp_dir:
        named_cache_manager.delete_symlinks(run_dir, options.named_caches)

  try:
    if options.isolate_server:
      storage = isolateserver.get_storage(
          options.isolate_server, options.namespace)
      with storage:
        # Hashing schemes used by |storage| and |isolate_cache| MUST match.
        assert storage.hash_algo == isolate_cache.hash_algo
        return run_tha_test(
            args,
            options.isolated,
            storage,
            isolate_cache,
            options.output,
            init_named_caches,
            options.leak_temp_dir,
            options.json, options.root_dir,
            options.hard_timeout,
            options.grace_period,
            options.bot_file,
            install_packages_fn,
            options.use_symlinks)
    return run_tha_test(
        args,
        options.isolated,
        None,
        isolate_cache,
        options.output,
        init_named_caches,
        options.leak_temp_dir,
        options.json,
        options.root_dir,
        options.hard_timeout,
        options.grace_period,
        options.bot_file,
        install_packages_fn,
        options.use_symlinks)
  except (cipd.Error, named_cache.Error) as ex:
    print >> sys.stderr, ex.message
    return 1


if __name__ == '__main__':
  subprocess42.inhibit_os_error_reporting()
  # Ensure that we are always running with the correct encoding.
  fix_encoding.fix_encoding()
  file_path.enable_symlink()

  sys.exit(main(sys.argv[1:]))

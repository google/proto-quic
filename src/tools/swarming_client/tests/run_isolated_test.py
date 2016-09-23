#!/usr/bin/env python
# Copyright 2013 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

# pylint: disable=R0201

import StringIO
import base64
import functools
import json
import logging
import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(
    __file__.decode(sys.getfilesystemencoding()))))
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, 'third_party'))

import cipd
import isolated_format
import isolateserver
import run_isolated
from depot_tools import auto_stub
from depot_tools import fix_encoding
from utils import file_path
from utils import fs
from utils import large
from utils import logging_utils
from utils import on_error
from utils import subprocess42
from utils import tools

import isolateserver_mock
import cipdserver_mock


def write_content(filepath, content):
  with open(filepath, 'wb') as f:
    f.write(content)


def json_dumps(data):
  return json.dumps(data, sort_keys=True, separators=(',', ':'))


class StorageFake(object):
  def __init__(self, files):
    self._files = files.copy()
    self.namespace = 'default-gzip'
    self.location = 'http://localhost:1'

  def __enter__(self, *_):
    return self

  def __exit__(self, *_):
    pass

  @property
  def hash_algo(self):
    return isolateserver_mock.ALGO

  def async_fetch(self, channel, _priority, digest, _size, sink):
    sink([self._files[digest]])
    channel.send_result(digest)

  def upload_items(self, items_to_upload):
    # Return all except the first one.
    return items_to_upload[1:]


class RunIsolatedTestBase(auto_stub.TestCase):
  def setUp(self):
    super(RunIsolatedTestBase, self).setUp()
    self.tempdir = tempfile.mkdtemp(prefix=u'run_isolated_test')
    logging.debug(self.tempdir)
    self.mock(run_isolated, 'make_temp_dir', self.fake_make_temp_dir)
    self.mock(run_isolated.auth, 'ensure_logged_in', lambda _: None)
    self.mock(
        logging_utils.OptionParserWithLogging, 'logger_root',
        logging.Logger('unittest'))

    self.cipd_server = cipdserver_mock.MockCipdServer()

  def tearDown(self):
    file_path.rmtree(self.tempdir)
    self.cipd_server.close()
    super(RunIsolatedTestBase, self).tearDown()

  @property
  def run_test_temp_dir(self):
    """Where to map all files in run_isolated.run_tha_test."""
    return os.path.join(self.tempdir, run_isolated.ISOLATED_RUN_DIR)

  def fake_make_temp_dir(self, prefix, _root_dir):
    """Predictably returns directory for run_tha_test (one per test case)."""
    self.assertIn(
        prefix,
        (run_isolated.ISOLATED_OUT_DIR, run_isolated.ISOLATED_RUN_DIR,
          run_isolated.ISOLATED_TMP_DIR, 'cipd_site_root'))
    temp_dir = os.path.join(self.tempdir, prefix)
    self.assertFalse(os.path.isdir(temp_dir))
    os.makedirs(temp_dir)
    return temp_dir

  def temp_join(self, *args):
    """Shortcut for joining path with self.run_test_temp_dir."""
    return os.path.join(self.run_test_temp_dir, *args)


class RunIsolatedTest(RunIsolatedTestBase):
  def setUp(self):
    super(RunIsolatedTest, self).setUp()
    # list of func(args, **kwargs) -> retcode
    # if the func returns None, then it's skipped. The first function to return
    # non-None is taken as the retcode for the mocked Popen call.
    self.popen_mocks = []
    self.popen_calls = []
    # pylint: disable=no-self-argument
    class Popen(object):
      def __init__(self2, args, **kwargs):
        kwargs.pop('cwd', None)
        kwargs.pop('env', None)
        self2.returncode = None
        self2.args = args
        self2.kwargs = kwargs
        self.popen_calls.append((args, kwargs))

      def yield_any_line(self, timeout=None):  # pylint: disable=unused-argument
        return ()

      def wait(self2, timeout=None):  # pylint: disable=unused-argument
        self2.returncode = 0
        for mock_fn in self.popen_mocks:
          ret = mock_fn(self2.args, **self2.kwargs)
          if ret is not None:
            self2.returncode = ret
            break
        return self2.returncode

      def kill(self):
        pass

    self.mock(subprocess42, 'Popen', Popen)

  def test_main(self):
    self.mock(tools, 'disable_buffering', lambda: None)
    isolated = json_dumps(
        {
          'command': ['foo.exe', 'cmd with space'],
        })
    isolated_hash = isolateserver_mock.hash_content(isolated)
    def get_storage(_isolate_server, _namespace):
      return StorageFake({isolated_hash:isolated})
    self.mock(isolateserver, 'get_storage', get_storage)

    cmd = [
        '--no-log',
        '--isolated', isolated_hash,
        '--cache', self.tempdir,
        '--isolate-server', 'https://localhost',
    ]
    ret = run_isolated.main(cmd)
    self.assertEqual(0, ret)
    self.assertEqual(
        [([self.temp_join(u'foo.exe'), u'cmd with space'], {'detached': True})],
        self.popen_calls)

  def test_main_args(self):
    self.mock(tools, 'disable_buffering', lambda: None)
    isolated = json_dumps({'command': ['foo.exe', 'cmd w/ space']})
    isolated_hash = isolateserver_mock.hash_content(isolated)
    def get_storage(_isolate_server, _namespace):
      return StorageFake({isolated_hash:isolated})
    self.mock(isolateserver, 'get_storage', get_storage)

    cmd = [
        '--use-symlinks',
        '--no-log',
        '--isolated', isolated_hash,
        '--cache', self.tempdir,
        '--isolate-server', 'https://localhost',
        '--',
        '--extraargs',
        'bar',
    ]
    ret = run_isolated.main(cmd)
    self.assertEqual(0, ret)
    self.assertEqual(
        [
          ([self.temp_join(u'foo.exe'), u'cmd w/ space', '--extraargs', 'bar'],
            {'detached': True}),
          ],
        self.popen_calls)

  def _run_tha_test(self, isolated_hash=None, files=None, command=None):
    files = files or {}
    make_tree_call = []
    def add(i, _):
      make_tree_call.append(i)
    for i in ('make_tree_read_only', 'make_tree_files_read_only',
              'make_tree_deleteable', 'make_tree_writeable'):
      self.mock(file_path, i, functools.partial(add, i))

    ret = run_isolated.run_tha_test(
        command,
        isolated_hash,
        StorageFake(files),
        isolateserver.MemoryCache(),
        False,
        None,
        None,
        None,
        None,
        None,
        None,
        lambda run_dir: None,
        False)
    self.assertEqual(0, ret)
    return make_tree_call

  def test_run_tha_test_naked(self):
    isolated = json_dumps({'command': ['invalid', 'command']})
    isolated_hash = isolateserver_mock.hash_content(isolated)
    files = {isolated_hash:isolated}
    make_tree_call = self._run_tha_test(isolated_hash, files)
    self.assertEqual(
        [
          'make_tree_writeable', 'make_tree_deleteable', 'make_tree_deleteable',
          'make_tree_deleteable',
        ],
        make_tree_call)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([self.temp_join(u'invalid'), u'command'], {'detached': True})],
        self.popen_calls)

  def test_run_tha_test_naked_read_only_0(self):
    isolated = json_dumps(
        {
          'command': ['invalid', 'command'],
          'read_only': 0,
        })
    isolated_hash = isolateserver_mock.hash_content(isolated)
    files = {isolated_hash:isolated}
    make_tree_call = self._run_tha_test(isolated_hash, files)
    self.assertEqual(
        [
          'make_tree_writeable', 'make_tree_deleteable', 'make_tree_deleteable',
          'make_tree_deleteable',
        ],
        make_tree_call)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([self.temp_join(u'invalid'), u'command'], {'detached': True})],
        self.popen_calls)

  def test_run_tha_test_naked_read_only_1(self):
    isolated = json_dumps(
        {
          'command': ['invalid', 'command'],
          'read_only': 1,
        })
    isolated_hash = isolateserver_mock.hash_content(isolated)
    files = {isolated_hash:isolated}
    make_tree_call = self._run_tha_test(isolated_hash, files)
    self.assertEqual(
        [
          'make_tree_files_read_only', 'make_tree_deleteable',
          'make_tree_deleteable', 'make_tree_deleteable',
        ],
        make_tree_call)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([self.temp_join(u'invalid'), u'command'], {'detached': True})],
        self.popen_calls)

  def test_run_tha_test_naked_read_only_2(self):
    isolated = json_dumps(
        {
          'command': ['invalid', 'command'],
          'read_only': 2,
        })
    isolated_hash = isolateserver_mock.hash_content(isolated)
    files = {isolated_hash:isolated}
    make_tree_call = self._run_tha_test(isolated_hash, files)
    self.assertEqual(
        [
          'make_tree_read_only', 'make_tree_deleteable', 'make_tree_deleteable',
          'make_tree_deleteable',
        ],
        make_tree_call)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([self.temp_join(u'invalid'), u'command'], {'detached': True})],
        self.popen_calls)

  def mock_popen_with_oserr(self):
    def r(self, args, **kwargs):
      old_init(self, args, **kwargs)
      raise OSError('Unknown')
    old_init = self.mock(subprocess42.Popen, '__init__', r)

  def test_main_naked(self):
    self.mock_popen_with_oserr()
    self.mock(on_error, 'report', lambda _: None)
    # The most naked .isolated file that can exist.
    self.mock(tools, 'disable_buffering', lambda: None)
    isolated = json_dumps({'command': ['invalid', 'command']})
    isolated_hash = isolateserver_mock.hash_content(isolated)
    def get_storage(_isolate_server, _namespace):
      return StorageFake({isolated_hash:isolated})
    self.mock(isolateserver, 'get_storage', get_storage)

    cmd = [
        '--no-log',
        '--isolated', isolated_hash,
        '--cache', self.tempdir,
        '--isolate-server', 'https://localhost',
    ]
    ret = run_isolated.main(cmd)
    self.assertEqual(1, ret)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([self.temp_join(u'invalid'), u'command'], {'detached': True})],
        self.popen_calls)

  def test_main_naked_without_isolated(self):
    self.mock_popen_with_oserr()
    cmd = [
      '--no-log',
      '--cache', self.tempdir,
      '/bin/echo',
      'hello',
      'world',
    ]
    ret = run_isolated.main(cmd)
    self.assertEqual(1, ret)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([u'/bin/echo', u'hello', u'world'], {'detached': True})],
        self.popen_calls)

  def test_main_naked_with_packages(self):
    pin_idx_ref = [0]
    pins = [
      [
        ('infra/data/x', 'badc0fee'*5),
        ('infra/data/y', 'cafebabe'*5),
      ],
      [
        ('infra/tools/echo/linux-amd64', 'deadbeef'*5),
      ],
    ]

    def fake_ensure(args, **_kwargs):
      if (args[0].endswith('/cipd') and
          args[1] == 'ensure'
          and '-json-output' in args):
        idx = args.index('-json-output')
        with open(args[idx+1], 'w') as json_out:
          json.dump({
            'result': [
              {'package': pkg, 'instance_id': ver}
              for pkg, ver in pins[pin_idx_ref[0]]
            ],
          }, json_out)
        pin_idx_ref[0] += 1
        return 0

    self.popen_mocks.append(fake_ensure)
    cipd_cache = os.path.join(self.tempdir, 'cipd_cache')
    cmd = [
      '--no-log',
      '--cache', os.path.join(self.tempdir, 'cache'),
      '--cipd-client-version', 'git:wowza',
      '--cipd-package', 'bin:infra/tools/echo/${platform}:latest',
      '--cipd-package', '.:infra/data/x:latest',
      '--cipd-package', '.:infra/data/y:canary',
      '--cipd-server', self.cipd_server.url,
      '--cipd-cache', cipd_cache,
      'bin/echo${EXECUTABLE_SUFFIX}',
      'hello',
      'world',
    ]
    ret = run_isolated.main(cmd)
    self.assertEqual(0, ret)

    self.assertEqual(3, len(self.popen_calls))

    # Test cipd-ensure command for installing packages.
    for cipd_ensure_cmd, _ in self.popen_calls[0:2]:
      self.assertEqual(cipd_ensure_cmd[:2], [
        os.path.join(cipd_cache, 'cipd' + cipd.EXECUTABLE_SUFFIX),
        'ensure',
      ])
      cache_dir_index = cipd_ensure_cmd.index('-cache-dir')
      self.assertEqual(
          cipd_ensure_cmd[cache_dir_index+1],
          os.path.join(cipd_cache, 'cipd_internal'))

    # Test cipd client cache. `git:wowza` was a tag and so is cacheable.
    self.assertEqual(len(os.listdir(os.path.join(cipd_cache, 'versions'))), 2)
    version_file = unicode(os.path.join(
        cipd_cache, 'versions', '633d2aa4119cc66803f1600f9c4d85ce0e0581b5'))
    self.assertTrue(fs.isfile(version_file))
    with open(version_file) as f:
      self.assertEqual(f.read(), 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

    client_binary_file = unicode(os.path.join(
        cipd_cache, 'clients', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    self.assertTrue(fs.isfile(client_binary_file))

    # Test echo call.
    echo_cmd, _ = self.popen_calls[2]
    self.assertTrue(echo_cmd[0].endswith(
        os.path.sep + 'bin' + os.path.sep + 'echo' + cipd.EXECUTABLE_SUFFIX),
        echo_cmd[0])
    self.assertEqual(echo_cmd[1:], ['hello', 'world'])

  def test_modified_cwd(self):
    isolated = json_dumps({
        'command': ['../out/some.exe', 'arg'],
        'relative_cwd': 'some',
    })
    isolated_hash = isolateserver_mock.hash_content(isolated)
    files = {isolated_hash:isolated}
    _ = self._run_tha_test(isolated_hash, files)
    self.assertEqual(1, len(self.popen_calls))
    self.assertEqual(
        [([self.temp_join(u'out', u'some.exe'), 'arg'], {'detached': True})],
        self.popen_calls)

  def test_python_cmd(self):
    isolated = json_dumps({
        'command': ['../out/cmd.py', 'arg'],
        'relative_cwd': 'some',
    })
    isolated_hash = isolateserver_mock.hash_content(isolated)
    files = {isolated_hash:isolated}
    _ = self._run_tha_test(isolated_hash, files)
    self.assertEqual(1, len(self.popen_calls))
    # Injects sys.executable.
    self.assertEqual(
        [
          ([sys.executable, os.path.join(u'..', 'out', 'cmd.py'), u'arg'],
            {'detached': True}),
        ],
        self.popen_calls)

  def test_run_tha_test_non_isolated(self):
    _ = self._run_tha_test(command=['/bin/echo', 'hello', 'world'])
    self.assertEqual(
        [([u'/bin/echo', u'hello', u'world'], {'detached': True})],
        self.popen_calls)


class RunIsolatedTestRun(RunIsolatedTestBase):
  def test_output(self):
    # Starts a full isolate server mock and have run_tha_test() uploads results
    # back after the task completed.
    server = isolateserver_mock.MockIsolateServer()
    try:
      script = (
        'import sys\n'
        'open(sys.argv[1], "w").write("bar")\n')
      script_hash = isolateserver_mock.hash_content(script)
      isolated = {
        'algo': 'sha-1',
        'command': ['cmd.py', '${ISOLATED_OUTDIR}/foo'],
        'files': {
          'cmd.py': {
            'h': script_hash,
            'm': 0700,
            's': len(script),
          },
        },
        'version': isolated_format.ISOLATED_FILE_VERSION,
      }
      if sys.platform == 'win32':
        isolated['files']['cmd.py'].pop('m')
      isolated_data = json_dumps(isolated)
      isolated_hash = isolateserver_mock.hash_content(isolated_data)
      server.add_content('default-store', script)
      server.add_content('default-store', isolated_data)
      store = isolateserver.get_storage(server.url, 'default-store')

      self.mock(sys, 'stdout', StringIO.StringIO())
      ret = run_isolated.run_tha_test(
          None,
          isolated_hash,
          store,
          isolateserver.MemoryCache(),
          False,
          None,
          None,
          None,
          None,
          None,
          None,
          lambda run_dir: None,
          False)
      self.assertEqual(0, ret)

      # It uploaded back. Assert the store has a new item containing foo.
      hashes = {isolated_hash, script_hash}
      output_hash = isolateserver_mock.hash_content('bar')
      hashes.add(output_hash)
      isolated =  {
        'algo': 'sha-1',
        'files': {
          'foo': {
            'h': output_hash,
            # TODO(maruel): Handle umask.
            'm': 0640,
            's': 3,
          },
        },
        'version': isolated_format.ISOLATED_FILE_VERSION,
      }
      if sys.platform == 'win32':
        isolated['files']['foo'].pop('m')
      uploaded = json_dumps(isolated)
      uploaded_hash = isolateserver_mock.hash_content(uploaded)
      hashes.add(uploaded_hash)
      self.assertEqual(hashes, set(server.contents['default-store']))

      expected = ''.join([
        '[run_isolated_out_hack]',
        '{"hash":"%s","namespace":"default-store","storage":%s}' % (
            uploaded_hash, json.dumps(server.url)),
        '[/run_isolated_out_hack]'
      ]) + '\n'
      self.assertEqual(expected, sys.stdout.getvalue())
    finally:
      server.close()


class RunIsolatedJsonTest(RunIsolatedTestBase):
  # Similar to RunIsolatedTest but adds the hacks to process ISOLATED_OUTDIR to
  # generate a json result file.
  def setUp(self):
    super(RunIsolatedJsonTest, self).setUp()
    self.popen_calls = []

    # pylint: disable=no-self-argument
    class Popen(object):
      def __init__(self2, args, **kwargs):
        kwargs.pop('cwd', None)
        kwargs.pop('env', None)
        self.popen_calls.append((args, kwargs))
        # Assume ${ISOLATED_OUTDIR} is the last one for testing purpose.
        self2._path = args[-1]
        self2.returncode = None

      def wait(self, timeout=None):  # pylint: disable=unused-argument
        self.returncode = 0
        with open(self._path, 'wb') as f:
          f.write('generated data\n')
        return self.returncode

      def kill(self):
        pass

    self.mock(subprocess42, 'Popen', Popen)

  def test_main_json(self):
    # Instruct the Popen mock to write a file in ISOLATED_OUTDIR so it will be
    # archived back on termination.
    self.mock(tools, 'disable_buffering', lambda: None)
    sub_cmd = [
      self.temp_join(u'foo.exe'), u'cmd with space',
      '${ISOLATED_OUTDIR}/out.txt',
    ]
    isolated_in_json = json_dumps({'command': sub_cmd})
    isolated_in_hash = isolateserver_mock.hash_content(isolated_in_json)
    def get_storage(_isolate_server, _namespace):
      return StorageFake({isolated_in_hash:isolated_in_json})
    self.mock(isolateserver, 'get_storage', get_storage)

    out = os.path.join(self.tempdir, 'res.json')
    cmd = [
        '--no-log',
        '--isolated', isolated_in_hash,
        '--cache', self.tempdir,
        '--isolate-server', 'https://localhost:1',
        '--json', out,
    ]
    ret = run_isolated.main(cmd)
    self.assertEqual(0, ret)
    # Replace ${ISOLATED_OUTDIR} with the temporary directory.
    sub_cmd[2] = self.popen_calls[0][0][2]
    self.assertNotIn('ISOLATED_OUTDIR', sub_cmd[2])
    self.assertEqual([(sub_cmd, {'detached': True})], self.popen_calls)
    isolated_out = {
      'algo': 'sha-1',
      'files': {
        'out.txt': {
          'h': isolateserver_mock.hash_content('generated data\n'),
          's': 15,
          'm': 0640,
        },
      },
      'version': isolated_format.ISOLATED_FILE_VERSION,
    }
    if sys.platform == 'win32':
      del isolated_out['files']['out.txt']['m']
    isolated_out_json = json_dumps(isolated_out)
    isolated_out_hash = isolateserver_mock.hash_content(isolated_out_json)
    expected = {
      u'exit_code': 0,
      u'had_hard_timeout': False,
      u'internal_failure': None,
      u'outputs_ref': {
        u'isolated': unicode(isolated_out_hash),
        u'isolatedserver': u'http://localhost:1',
        u'namespace': u'default-gzip',
      },
      u'stats': {
        u'isolated': {
          u'download': {
            u'initial_number_items': 0,
            u'initial_size': 0,
            u'items_cold': [len(isolated_in_json)],
            u'items_hot': [],
          },
          u'upload': {
            u'items_cold': [len(isolated_out_json)],
            u'items_hot': [15],
          },
        },
      },
      u'version': 5,
    }
    actual = tools.read_json(out)
    # duration can be exactly 0 due to low timer resolution, especially but not
    # exclusively on Windows.
    self.assertLessEqual(0, actual.pop(u'duration'))
    actual_isolated_stats = actual[u'stats'][u'isolated']
    self.assertLessEqual(0, actual_isolated_stats[u'download'].pop(u'duration'))
    self.assertLessEqual(0, actual_isolated_stats[u'upload'].pop(u'duration'))
    for i in (u'download', u'upload'):
      for j in (u'items_cold', u'items_hot'):
        actual_isolated_stats[i][j] = large.unpack(
            base64.b64decode(actual_isolated_stats[i][j]))
    self.assertEqual(expected, actual)


if __name__ == '__main__':
  fix_encoding.fix_encoding()
  if '-v' in sys.argv:
    unittest.TestCase.maxDiff = None
  logging.basicConfig(
      level=logging.DEBUG if '-v' in sys.argv else logging.ERROR)
  unittest.main()

#!/usr/bin/env python
# Copyright 2013 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

# pylint: disable=W0212,W0223,W0231,W0613

import base64
import hashlib
import json
import logging
import io
import os
import StringIO
import sys
import tarfile
import tempfile
import unittest
import zlib

# net_utils adjusts sys.path.
import net_utils

import auth
import isolated_format
import isolateserver
import isolate_storage
import test_utils
from depot_tools import fix_encoding
from utils import file_path
from utils import fs
from utils import logging_utils
from utils import threading_utils

import isolateserver_mock


CONTENTS = {
  'empty_file.txt': '',
  'small_file.txt': 'small file\n',
  # TODO(maruel): symlinks.
}


class TestCase(net_utils.TestCase):
  """Mocks out url_open() calls and sys.stdout/stderr."""
  _tempdir = None

  def setUp(self):
    super(TestCase, self).setUp()
    self.mock(auth, 'ensure_logged_in', lambda _: None)
    self.mock(sys, 'stdout', StringIO.StringIO())
    self.mock(sys, 'stderr', StringIO.StringIO())
    self.old_cwd = os.getcwd()

  def tearDown(self):
    try:
      os.chdir(self.old_cwd)
      if self._tempdir:
        file_path.rmtree(self._tempdir)
      if not self.has_failed():
        self.checkOutput('', '')
    finally:
      super(TestCase, self).tearDown()

  @property
  def tempdir(self):
    if not self._tempdir:
      self._tempdir = tempfile.mkdtemp(prefix=u'isolateserver')
    return self._tempdir

  def make_tree(self, contents):
    test_utils.make_tree(self.tempdir, contents)

  def checkOutput(self, expected_out, expected_err):
    try:
      self.assertEqual(expected_err, sys.stderr.getvalue())
      self.assertEqual(expected_out, sys.stdout.getvalue())
    finally:
      # Prevent double-fail.
      self.mock(sys, 'stdout', StringIO.StringIO())
      self.mock(sys, 'stderr', StringIO.StringIO())


class TestZipCompression(TestCase):
  """Test zip_compress and zip_decompress generators."""

  def test_compress_and_decompress(self):
    """Test data === decompress(compress(data))."""
    original = [str(x) for x in xrange(0, 1000)]
    processed = isolateserver.zip_decompress(
        isolateserver.zip_compress(original))
    self.assertEqual(''.join(original), ''.join(processed))

  def test_zip_bomb(self):
    """Verify zip_decompress always returns small chunks."""
    original = '\x00' * 100000
    bomb = ''.join(isolateserver.zip_compress(original))
    decompressed = []
    chunk_size = 1000
    for chunk in isolateserver.zip_decompress([bomb], chunk_size):
      self.assertLessEqual(len(chunk), chunk_size)
      decompressed.append(chunk)
    self.assertEqual(original, ''.join(decompressed))

  def test_bad_zip_file(self):
    """Verify decompressing broken file raises IOError."""
    with self.assertRaises(IOError):
      ''.join(isolateserver.zip_decompress(['Im not a zip file']))


class FakeItem(isolateserver.Item):
  def __init__(self, data, high_priority=False):
    super(FakeItem, self).__init__(
      isolateserver_mock.hash_content(data), len(data), high_priority)
    self.data = data

  def content(self):
    return [self.data]

  @property
  def zipped(self):
    return zlib.compress(self.data, self.compression_level)


class MockedStorageApi(isolate_storage.StorageApi):
  def __init__(
      self, missing_hashes, push_side_effect=None, namespace='default'):
    self.missing_hashes = missing_hashes
    self.push_side_effect = push_side_effect
    self.push_calls = []
    self.contains_calls = []
    self._namespace = namespace

  @property
  def namespace(self):
    return self._namespace

  def push(self, item, push_state, content=None):
    content = ''.join(item.content() if content is None else content)
    self.push_calls.append((item, push_state, content))
    if self.push_side_effect:
      self.push_side_effect()

  def contains(self, items):
    self.contains_calls.append(items)
    missing = {}
    for item in items:
      if item.digest in self.missing_hashes:
        missing[item] = self.missing_hashes[item.digest]
    return missing


class UtilsTest(TestCase):
  """Tests for helper methods in isolateserver file."""

  def assertFile(self, path, contents):
    self.assertTrue(fs.exists(path), 'File %s doesn\'t exist!' % path)
    self.assertMultiLineEqual(contents, fs.open(path, 'rb').read())

  def test_file_read(self):
    # TODO(maruel): Write test for file_read generator (or remove it).
    pass

  def test_file_write(self):
    # TODO(maruel): Write test for file_write generator (or remove it).
    pass

  def test_fileobj_path(self):
    # No path on in-memory objects
    self.assertIs(None, isolateserver.fileobj_path(io.BytesIO('hello')))

    # Path on opened files
    thisfile = os.path.abspath(__file__.decode(sys.getfilesystemencoding()))
    f = fs.open(thisfile)
    result = isolateserver.fileobj_path(f)
    self.assertIsInstance(result, unicode)
    self.assertSequenceEqual(result, thisfile)

    # Path on temporary files
    tf = tempfile.NamedTemporaryFile()
    result = isolateserver.fileobj_path(tf)
    self.assertIsInstance(result, unicode)
    self.assertSequenceEqual(result, tf.name)

    # No path on files which are no longer on the file system
    tf = tempfile.NamedTemporaryFile(delete=False)
    fs.unlink(tf.name.decode(sys.getfilesystemencoding()))
    self.assertIs(None, isolateserver.fileobj_path(tf))

  def test_fileobj_copy_simple(self):
    inobj = io.BytesIO('hello')
    outobj = io.BytesIO()

    isolateserver.fileobj_copy(outobj, inobj)
    self.assertEqual('hello', outobj.getvalue())

  def test_fileobj_copy_partial(self):
    inobj = io.BytesIO('adatab')
    outobj = io.BytesIO()
    inobj.read(1)

    isolateserver.fileobj_copy(outobj, inobj, size=4)
    self.assertEqual('data', outobj.getvalue())

  def test_fileobj_copy_partial_file_no_size(self):
    with self.assertRaises(IOError):
      inobj = io.BytesIO('hello')
      outobj = io.BytesIO()

      inobj.read(1)
      isolateserver.fileobj_copy(outobj, inobj)

  def test_fileobj_copy_size_but_file_short(self):
    with self.assertRaises(IOError):
      inobj = io.BytesIO('hello')
      outobj = io.BytesIO()

      isolateserver.fileobj_copy(outobj, inobj, size=10)

  def test_putfile(self):
    tmpoutdir = None
    tmpindir = None

    try:
      tmpindir = tempfile.mkdtemp(prefix='isolateserver_test')
      infile = os.path.join(tmpindir, u'in')
      with fs.open(infile, 'wb') as f:
        f.write('data')

      tmpoutdir = tempfile.mkdtemp(prefix='isolateserver_test')

      # Copy as fileobj
      fo = os.path.join(tmpoutdir, u'fo')
      isolateserver.putfile(io.BytesIO('data'), fo)
      self.assertEqual(True, fs.exists(fo))
      self.assertEqual(False, fs.islink(fo))
      self.assertFile(fo, 'data')

      # Copy with partial fileobj
      pfo = os.path.join(tmpoutdir, u'pfo')
      fobj = io.BytesIO('adatab')
      fobj.read(1)  # Read the 'a'
      isolateserver.putfile(fobj, pfo, size=4)
      self.assertEqual(True, fs.exists(pfo))
      self.assertEqual(False, fs.islink(pfo))
      self.assertEqual('b', fobj.read())
      self.assertFile(pfo, 'data')

      # Copy as not readonly
      cp = os.path.join(tmpoutdir, u'cp')
      with fs.open(infile, 'rb') as f:
        isolateserver.putfile(f, cp, file_mode=0755)
      self.assertEqual(True, fs.exists(cp))
      self.assertEqual(False, fs.islink(cp))
      self.assertFile(cp, 'data')

      # Use hardlink
      hl = os.path.join(tmpoutdir, u'hl')
      with fs.open(infile, 'rb') as f:
        isolateserver.putfile(f, hl, use_symlink=False)
      self.assertEqual(True, fs.exists(hl))
      self.assertEqual(False, fs.islink(hl))
      self.assertFile(hl, 'data')

      # Use symlink
      sl = os.path.join(tmpoutdir, u'sl')
      with fs.open(infile, 'rb') as f:
        isolateserver.putfile(f, sl, use_symlink=True)
      self.assertEqual(True, fs.exists(sl))
      self.assertEqual(True, fs.islink(sl))
      self.assertEqual('data', fs.open(sl, 'rb').read())
      self.assertFile(sl, 'data')

    finally:
      if tmpindir:
        file_path.rmtree(tmpindir)
      if tmpoutdir:
        file_path.rmtree(tmpoutdir)


class StorageTest(TestCase):
  """Tests for Storage methods."""

  def assertEqualIgnoringOrder(self, a, b):
    """Asserts that containers |a| and |b| contain same items."""
    self.assertEqual(len(a), len(b))
    self.assertEqual(set(a), set(b))

  def get_push_state(self, storage, item):
    missing = list(storage.get_missing_items([item]))
    self.assertEqual(1, len(missing))
    self.assertEqual(item, missing[0][0])
    return missing[0][1]

  def test_batch_items_for_check(self):
    items = [
      isolateserver.Item('foo', 12),
      isolateserver.Item('blow', 0),
      isolateserver.Item('bizz', 1222),
      isolateserver.Item('buzz', 1223),
    ]
    expected = [
      [items[3], items[2], items[0], items[1]],
    ]
    batches = list(isolateserver.batch_items_for_check(items))
    self.assertEqual(batches, expected)

  def test_get_missing_items(self):
    items = [
      isolateserver.Item('foo', 12),
      isolateserver.Item('blow', 0),
      isolateserver.Item('bizz', 1222),
      isolateserver.Item('buzz', 1223),
    ]
    missing = {
      items[2]: 123,
      items[3]: 456,
    }

    storage_api = MockedStorageApi(
        {item.digest: push_state for item, push_state in missing.iteritems()})
    storage = isolateserver.Storage(storage_api)

    # 'get_missing_items' is a generator yielding pairs, materialize its
    # result in a dict.
    result = dict(storage.get_missing_items(items))
    self.assertEqual(missing, result)

  def test_async_push(self):
    for use_zip in (False, True):
      item = FakeItem('1234567')
      storage_api = MockedStorageApi(
          {item.digest: 'push_state'},
          namespace='default-gzip' if use_zip else 'default')
      storage = isolateserver.Storage(storage_api)
      channel = threading_utils.TaskChannel()
      storage.async_push(channel, item, self.get_push_state(storage, item))
      # Wait for push to finish.
      pushed_item = channel.pull()
      self.assertEqual(item, pushed_item)
      # StorageApi.push was called with correct arguments.
      self.assertEqual(
          [(item, 'push_state', item.zipped if use_zip else item.data)],
          storage_api.push_calls)

  def test_async_push_generator_errors(self):
    class FakeException(Exception):
      pass

    def faulty_generator():
      yield 'Hi!'
      raise FakeException('fake exception')

    for use_zip in (False, True):
      item = FakeItem('')
      self.mock(item, 'content', faulty_generator)
      storage_api = MockedStorageApi(
          {item.digest: 'push_state'},
          namespace='default-gzip' if use_zip else 'default')
      storage = isolateserver.Storage(storage_api)
      channel = threading_utils.TaskChannel()
      storage.async_push(channel, item, self.get_push_state(storage, item))
      with self.assertRaises(FakeException):
        channel.pull()
      # StorageApi's push should never complete when data can not be read.
      self.assertEqual(0, len(storage_api.push_calls))

  def test_async_push_upload_errors(self):
    chunk = 'data_chunk'

    def _generator():
      yield chunk

    def push_side_effect():
      raise IOError('Nope')

    # TODO(vadimsh): Retrying push when fetching data from a generator is
    # broken now (it reuses same generator instance when retrying).
    content_sources = (
        # generator(),
        lambda: [chunk],
    )

    for use_zip in (False, True):
      for source in content_sources:
        item = FakeItem(chunk)
        self.mock(item, 'content', source)
        storage_api = MockedStorageApi(
            {item.digest: 'push_state'},
            push_side_effect,
            namespace='default-gzip' if use_zip else 'default')
        storage = isolateserver.Storage(storage_api)
        channel = threading_utils.TaskChannel()
        storage.async_push(channel, item, self.get_push_state(storage, item))
        with self.assertRaises(IOError):
          channel.pull()
        # First initial attempt + all retries.
        attempts = 1 + storage.net_thread_pool.RETRIES
        # Single push attempt call arguments.
        expected_push = (
            item, 'push_state', item.zipped if use_zip else item.data)
        # Ensure all pushes are attempted.
        self.assertEqual(
            [expected_push] * attempts, storage_api.push_calls)

  def test_upload_tree(self):
    files = {
      u'/a': {
        's': 100,
        'h': 'hash_a',
      },
      u'/some/dir/b': {
        's': 200,
        'h': 'hash_b',
      },
      u'/another/dir/c': {
        's': 300,
        'h': 'hash_c',
      },
      u'/a_copy': {
        's': 100,
        'h': 'hash_a',
      },
    }
    files_data = {k: 'x' * files[k]['s'] for k in files}
    all_hashes = set(f['h'] for f in files.itervalues())
    missing_hashes = {'hash_a': 'push a', 'hash_b': 'push b'}

    # Files read by mocked_file_read.
    read_calls = []

    def mocked_file_read(filepath, chunk_size=0, offset=0):
      self.assertIn(filepath, files_data)
      read_calls.append(filepath)
      return files_data[filepath]
    self.mock(isolateserver, 'file_read', mocked_file_read)

    storage_api = MockedStorageApi(missing_hashes)
    storage = isolateserver.Storage(storage_api)
    def mock_get_storage(base_url, namespace):
      self.assertEqual('base_url', base_url)
      self.assertEqual('some-namespace', namespace)
      return storage
    self.mock(isolateserver, 'get_storage', mock_get_storage)

    isolateserver.upload_tree('base_url', files.iteritems(), 'some-namespace')

    # Was reading only missing files.
    self.assertEqualIgnoringOrder(
        missing_hashes,
        [files[path]['h'] for path in read_calls])
    # 'contains' checked for existence of all files.
    self.assertEqualIgnoringOrder(
        all_hashes,
        [i.digest for i in sum(storage_api.contains_calls, [])])
    # Pushed only missing files.
    self.assertEqualIgnoringOrder(
        missing_hashes,
        [call[0].digest for call in storage_api.push_calls])
    # Pushing with correct data, size and push state.
    for pushed_item, push_state, pushed_content in storage_api.push_calls:
      filenames = [
          name for name, metadata in files.iteritems()
          if metadata['h'] == pushed_item.digest
      ]
      # If there are multiple files that map to same hash, upload_tree chooses
      # a first one.
      filename = filenames[0]
      self.assertEqual(filename, pushed_item.path)
      self.assertEqual(files_data[filename], pushed_content)
      self.assertEqual(missing_hashes[pushed_item.digest], push_state)


class IsolateServerStorageApiTest(TestCase):
  @staticmethod
  def mock_fetch_request(server, namespace, item, data=None, offset=0):
    compression = 'flate' if namespace.endswith(('-gzip', '-flate')) else ''
    if data is None:
      response = {'url': server + '/some/gs/url/%s/%s' % (namespace, item)}
    else:
      response = {'content': base64.b64encode(data[offset:])}
    return (
      server + '/api/isolateservice/v1/retrieve',
      {
          'data': {
              'digest': item,
              'namespace': {
                  'compression': compression,
                  'digest_hash': 'sha-1',
                  'namespace': namespace,
              },
              'offset': offset,
          },
          'read_timeout': 60,
      },
      response,
    )

  @staticmethod
  def mock_server_details_request(server):
    return (
        server + '/api/isolateservice/v1/server_details',
        {'data': {}},
        {'server_version': 'such a good version'}
    )

  @staticmethod
  def mock_gs_request(server, namespace, item, data=None, offset=0,
                      request_headers=None, response_headers=None):
    response = data
    return (
        server + '/some/gs/url/%s/%s' % (namespace, item),
        {},
        response,
        response_headers,
    )

  @staticmethod
  def mock_contains_request(
      server, namespace, request, response, compression=''):
    url = server + '/api/isolateservice/v1/preupload'
    digest_collection = dict(request, namespace={
        'compression': compression,
        'digest_hash': 'sha-1',
        'namespace': namespace,
    })
    return (url, {'data': digest_collection}, response)

  @staticmethod
  def mock_upload_request(server, content, ticket, response=None):
    url = server + '/api/isolateservice/v1/store_inline'
    request = {'content': content, 'upload_ticket': ticket}
    return (url, {'data': request}, response)

  def test_server_capabilities_success(self):
    server = 'http://example.com'
    namespace ='default'
    self.expected_requests([self.mock_server_details_request(server)])
    storage = isolate_storage.IsolateServer(server, namespace)
    caps = storage._server_capabilities
    self.assertEqual({'server_version': 'such a good version'}, caps)

  def test_fetch_success(self):
    server = 'http://example.com'
    namespace = 'default'
    data = ''.join(str(x) for x in xrange(1000))
    item = isolateserver_mock.hash_content(data)
    self.expected_requests(
        [self.mock_fetch_request(server, namespace, item, data)])
    storage = isolate_storage.IsolateServer(server, namespace)
    fetched = ''.join(storage.fetch(item))
    self.assertEqual(data, fetched)

  def test_fetch_failure(self):
    server = 'http://example.com'
    namespace = 'default'
    item = isolateserver_mock.hash_content('something')
    self.expected_requests(
        [self.mock_fetch_request(server, namespace, item)[:-1] + (None,)])
    storage = isolate_storage.IsolateServer(server, namespace)
    with self.assertRaises(IOError):
      _ = ''.join(storage.fetch(item))

  def test_fetch_offset_success(self):
    server = 'http://example.com'
    namespace = 'default'
    data = ''.join(str(x) for x in xrange(1000))
    item = isolateserver_mock.hash_content(data)
    offset = 200
    size = len(data)

    good_content_range_headers = [
      'bytes %d-%d/%d' % (offset, size - 1, size),
      'bytes %d-%d/*' % (offset, size - 1),
    ]

    for _content_range_header in good_content_range_headers:
      self.expected_requests([self.mock_fetch_request(
          server, namespace, item, data, offset=offset)])
      storage = isolate_storage.IsolateServer(server, namespace)
      fetched = ''.join(storage.fetch(item, offset))
      self.assertEqual(data[offset:], fetched)

  def test_fetch_offset_bad_header(self):
    server = 'http://example.com'
    namespace = 'default'
    data = ''.join(str(x) for x in xrange(1000))
    item = isolateserver_mock.hash_content(data)
    offset = 200
    size = len(data)

    bad_content_range_headers = [
      # Missing header.
      None,
      '',
      # Bad format.
      'not bytes %d-%d/%d' % (offset, size - 1, size),
      'bytes %d-%d' % (offset, size - 1),
      # Bad offset.
      'bytes %d-%d/%d' % (offset - 1, size - 1, size),
      # Incomplete chunk.
      'bytes %d-%d/%d' % (offset, offset + 10, size),
    ]

    for content_range_header in bad_content_range_headers:
      self.expected_requests([
          self.mock_fetch_request(
              server, namespace, item, offset=offset),
          self.mock_gs_request(
              server, namespace, item, data, offset=offset,
              request_headers={'Range': 'bytes=%d-' % offset},
              response_headers={'Content-Range': content_range_header}),
      ])
      storage = isolate_storage.IsolateServer(server, namespace)
      with self.assertRaises(IOError):
        _ = ''.join(storage.fetch(item, offset))

  def test_push_success(self):
    server = 'http://example.com'
    namespace = 'default'
    data = ''.join(str(x) for x in xrange(1000))
    item = FakeItem(data)
    contains_request = {'items': [
        {'digest': item.digest, 'size': item.size, 'is_isolated': 0}]}
    contains_response = {'items': [{'index': 0, 'upload_ticket': 'ticket!'}]}
    requests = [
      self.mock_contains_request(
          server, namespace, contains_request, contains_response),
      self.mock_upload_request(
          server,
          base64.b64encode(data),
          contains_response['items'][0]['upload_ticket'],
          {'ok': True},
      ),
    ]
    self.expected_requests(requests)
    storage = isolate_storage.IsolateServer(server, namespace)
    missing = storage.contains([item])
    self.assertEqual([item], missing.keys())
    push_state = missing[item]
    storage.push(item, push_state, [data])
    self.assertTrue(push_state.uploaded)
    self.assertTrue(push_state.finalized)

  def test_push_failure_upload(self):
    server = 'http://example.com'
    namespace = 'default'
    data = ''.join(str(x) for x in xrange(1000))
    item = FakeItem(data)
    contains_request = {'items': [
        {'digest': item.digest, 'size': item.size, 'is_isolated': 0}]}
    contains_response = {'items': [{'index': 0, 'upload_ticket': 'ticket!'}]}
    requests = [
      self.mock_contains_request(
          server, namespace, contains_request, contains_response),
      self.mock_upload_request(
          server,
          base64.b64encode(data),
          contains_response['items'][0]['upload_ticket'],
      ),
    ]
    self.expected_requests(requests)
    storage = isolate_storage.IsolateServer(server, namespace)
    missing = storage.contains([item])
    self.assertEqual([item], missing.keys())
    push_state = missing[item]
    with self.assertRaises(IOError):
      storage.push(item, push_state, [data])
    self.assertFalse(push_state.uploaded)
    self.assertFalse(push_state.finalized)

  def test_push_failure_finalize(self):
    server = 'http://example.com'
    namespace = 'default'
    data = ''.join(str(x) for x in xrange(1000))
    item = FakeItem(data)
    contains_request = {'items': [
        {'digest': item.digest, 'size': item.size, 'is_isolated': 0}]}
    contains_response = {'items': [
        {'index': 0,
         'gs_upload_url': server + '/FAKE_GCS/whatevs/1234',
         'upload_ticket': 'ticket!'}]}
    requests = [
      self.mock_contains_request(
          server, namespace, contains_request, contains_response),
      (
        server + '/FAKE_GCS/whatevs/1234',
        {
          'data': data,
          'content_type': 'application/octet-stream',
          'method': 'PUT',
          'headers': {'Cache-Control': 'public, max-age=31536000'},
        },
        '',
        None,
      ),
      (
        server + '/api/isolateservice/v1/finalize_gs_upload',
        {'data': {'upload_ticket': 'ticket!'}},
        None,
      ),
    ]
    self.expected_requests(requests)
    storage = isolate_storage.IsolateServer(server, namespace)
    missing = storage.contains([item])
    self.assertEqual([item], missing.keys())
    push_state = missing[item]
    with self.assertRaises(IOError):
      storage.push(item, push_state, [data])
    self.assertTrue(push_state.uploaded)
    self.assertFalse(push_state.finalized)

  def test_contains_success(self):
    server = 'http://example.com'
    namespace = 'default'
    files = [
      FakeItem('1', high_priority=True),
      FakeItem('2' * 100),
      FakeItem('3' * 200),
    ]
    request = {'items': [
        {'digest': f.digest, 'is_isolated': not i, 'size': f.size}
        for i, f in enumerate(files)]}
    response = {
        'items': [
            {'index': str(i), 'upload_ticket': 'ticket_%d' % i}
            for i in xrange(3)],
    }
    missing = [
        files[0],
        files[1],
        files[2],
    ]
    self._requests = [
      self.mock_contains_request(server, namespace, request, response),
    ]
    storage = isolate_storage.IsolateServer(server, namespace)
    result = storage.contains(files)
    self.assertEqual(set(missing), set(result.keys()))
    for i, (_item, push_state) in enumerate(result.iteritems()):
      self.assertEqual(
          push_state.upload_url, 'api/isolateservice/v1/store_inline')
      self.assertEqual(push_state.finalize_url, None)

  def test_contains_network_failure(self):
    server = 'http://example.com'
    namespace = 'default'
    self.expected_requests([self.mock_contains_request(
        server, namespace, {'items': []}, None)])
    storage = isolate_storage.IsolateServer(server, namespace)
    with self.assertRaises(isolated_format.MappingError):
      storage.contains([])

  def test_contains_format_failure(self):
    server = 'http://example.com'
    namespace = 'default'
    self.expected_requests([self.mock_contains_request(
        server, namespace, {'items': []}, None)])
    storage = isolate_storage.IsolateServer(server, namespace)
    with self.assertRaises(isolated_format.MappingError):
      storage.contains([])


class IsolateServerStorageSmokeTest(unittest.TestCase):
  """Tests public API of Storage class using file system as a store."""

  def setUp(self):
    super(IsolateServerStorageSmokeTest, self).setUp()
    self.tempdir = tempfile.mkdtemp(prefix=u'isolateserver')
    self.server = isolateserver_mock.MockIsolateServer()

  def tearDown(self):
    try:
      self.server.close_start()
      file_path.rmtree(self.tempdir)
      self.server.close_end()
    finally:
      super(IsolateServerStorageSmokeTest, self).tearDown()

  def run_synchronous_push_test(self, namespace):
    storage = isolateserver.get_storage(self.server.url, namespace)

    # Items to upload.
    items = [isolateserver.BufferItem('item %d' % i) for i in xrange(10)]

    # Storage is empty, all items are missing.
    missing = dict(storage.get_missing_items(items))
    self.assertEqual(set(items), set(missing))

    # Push, one by one.
    for item, push_state in missing.iteritems():
      storage.push(item, push_state)

    # All items are there now.
    self.assertFalse(dict(storage.get_missing_items(items)))

  def test_synchronous_push(self):
    self.run_synchronous_push_test('default')

  def test_synchronous_push_gzip(self):
    self.run_synchronous_push_test('default-gzip')

  def run_upload_items_test(self, namespace):
    storage = isolateserver.get_storage(self.server.url, namespace)

    # Items to upload.
    items = [isolateserver.BufferItem('item %d' % i) for i in xrange(10)]

    # Do it.
    uploaded = storage.upload_items(items)
    self.assertEqual(set(items), set(uploaded))

    # All items are there now.
    self.assertFalse(dict(storage.get_missing_items(items)))

    # Now ensure upload_items skips existing items.
    more = [isolateserver.BufferItem('more item %d' % i) for i in xrange(10)]

    # Uploaded only |more|.
    uploaded = storage.upload_items(items + more)
    self.assertEqual(set(more), set(uploaded))

  def test_upload_items(self):
    self.run_upload_items_test('default')

  def test_upload_items_gzip(self):
    self.run_upload_items_test('default-gzip')

  def run_push_and_fetch_test(self, namespace):
    storage = isolateserver.get_storage(self.server.url, namespace)

    # Upload items.
    items = [isolateserver.BufferItem('item %d' % i) for i in xrange(10)]
    uploaded = storage.upload_items(items)
    self.assertEqual(set(items), set(uploaded))

    # Fetch them all back into local memory cache.
    cache = isolateserver.MemoryCache()
    queue = isolateserver.FetchQueue(storage, cache)

    # Start fetching.
    pending = set()
    for item in items:
      pending.add(item.digest)
      queue.add(item.digest)

    # Wait for fetch to complete.
    while pending:
      fetched = queue.wait(pending)
      pending.discard(fetched)

    # Ensure fetched same data as was pushed.
    actual = []
    for i in items:
      with cache.getfileobj(i.digest) as f:
        actual.append(f.read())

    self.assertEqual([i.buffer for i in items], actual)

  def test_push_and_fetch(self):
    self.run_push_and_fetch_test('default')

  def test_push_and_fetch_gzip(self):
    self.run_push_and_fetch_test('default-gzip')

  if sys.maxsize == (2**31) - 1:
    def test_archive_multiple_huge_file(self):
      self.server.discard_content()
      # Create multiple files over 2.5gb. This test exists to stress the virtual
      # address space on 32 bits systems. Make real files since it wouldn't fit
      # memory by definition.
      # Sadly, this makes this test very slow so it's only run on 32 bits
      # platform, since it's known to work on 64 bits platforms anyway.
      #
      # It's a fairly slow test, well over 15 seconds.
      files = {}
      size = 512 * 1024 * 1024
      for i in xrange(5):
        name = '512mb_%d.%s' % (i, isolateserver.ALREADY_COMPRESSED_TYPES[0])
        p = os.path.join(self.tempdir, name)
        with open(p, 'wb') as f:
          # Write 512mb.
          h = hashlib.sha1()
          data = os.urandom(1024)
          for _ in xrange(size / 1024):
            f.write(data)
            h.update(data)
          os.chmod(p, 0600)
          files[p] = {
            'h': h.hexdigest(),
            'm': 0600,
            's': size,
          }
          if sys.platform == 'win32':
            files[p].pop('m')

      # upload_tree() is a thin wrapper around Storage.
      isolateserver.upload_tree(self.server.url, files.items(), 'testing')
      expected = {'testing': {f['h']: '<skipped>' for f in files.itervalues()}}
      self.assertEqual(expected, self.server.contents)


class IsolateServerDownloadTest(TestCase):

  def _url_read_json(self, url, **kwargs):
    """Current _url_read_json mock doesn't respect identical URLs."""
    logging.warn('url_read_json(%s, %s)', url[:500], str(kwargs)[:500])
    with self._lock:
      if not self._requests:
        return None
      if not self._flagged_requests:
        self._flagged_requests = [0 for _element in self._requests]
      # Ignore 'stream' argument, it's not important for these tests.
      kwargs.pop('stream', None)
      for i, (new_url, expected_kwargs, result) in enumerate(self._requests):
        if new_url == url and expected_kwargs == kwargs:
          self._flagged_requests[i] = 1
          return result
    self.fail('Unknown request %s' % url)

  def setUp(self):
    super(IsolateServerDownloadTest, self).setUp()
    self._flagged_requests = []
    self.mock(logging_utils, 'prepare_logging', lambda *_: None)
    self.mock(logging_utils, 'set_console_level', lambda *_: None)

  def tearDown(self):
    if all(self._flagged_requests):
      self._requests = []
    super(IsolateServerDownloadTest, self).tearDown()

  def test_download_two_files(self):
    # Test downloading two files.
    actual = {}
    def out(key, generator):
      actual[key] = ''.join(generator)
    self.mock(isolateserver, 'file_write', out)
    server = 'http://example.com'
    requests = [
      (
        server + '/api/isolateservice/v1/retrieve',
        {
            'data': {
                'digest': h.encode('utf-8'),
                'namespace': {
                    'namespace': 'default-gzip',
                    'digest_hash': 'sha-1',
                    'compression': 'flate',
                },
                'offset': 0,
            },
            'read_timeout': 60,
        },
        {'content': base64.b64encode(zlib.compress(v))},
      ) for h, v in [('sha-1', 'Coucou'), ('sha-2', 'Bye Bye')]
    ]
    self.expected_requests(requests)
    cmd = [
      'download',
      '--isolate-server', server,
      '--target', net_utils.ROOT_DIR,
      '--file', 'sha-1', 'path/to/a',
      '--file', 'sha-2', 'path/to/b',
    ]
    self.assertEqual(0, isolateserver.main(cmd))
    expected = {
      os.path.join(net_utils.ROOT_DIR, 'path/to/a'): 'Coucou',
      os.path.join(net_utils.ROOT_DIR, 'path/to/b'): 'Bye Bye',
    }
    self.assertEqual(expected, actual)

  def test_download_isolated_simple(self):
    # Test downloading an isolated tree.
    actual = {}
    def putfile_mock(
        srcfileobj, dstpath, file_mode=None, size=-1, use_symlink=False):
      actual[dstpath] = srcfileobj.read()
    self.mock(isolateserver, 'putfile', putfile_mock)
    self.mock(os, 'makedirs', lambda _: None)
    server = 'http://example.com'
    files = {
      os.path.join('a', 'foo'): 'Content',
      'b': 'More content',
    }
    isolated = {
      'command': ['Absurb', 'command'],
      'relative_cwd': 'a',
      'files': dict(
          (k, {'h': isolateserver_mock.hash_content(v), 's': len(v)})
          for k, v in files.iteritems()),
      'version': isolated_format.ISOLATED_FILE_VERSION,
    }
    isolated_data = json.dumps(isolated, sort_keys=True, separators=(',',':'))
    isolated_hash = isolateserver_mock.hash_content(isolated_data)
    requests = [(v['h'], files[k]) for k, v in isolated['files'].iteritems()]
    requests.append((isolated_hash, isolated_data))
    requests = [
      (
        server + '/api/isolateservice/v1/retrieve',
        {
            'data': {
                'digest': h.encode('utf-8'),
                'namespace': {
                    'namespace': 'default-gzip',
                    'digest_hash': 'sha-1',
                    'compression': 'flate',
                },
                'offset': 0,
            },
            'read_timeout': 60,
        },
        {'content': base64.b64encode(zlib.compress(v))},
      ) for h, v in requests
    ]
    cmd = [
      'download',
      '--isolate-server', server,
      '--target', self.tempdir,
      '--isolated', isolated_hash,
    ]
    self.expected_requests(requests)
    self.assertEqual(0, isolateserver.main(cmd))
    expected = dict(
        (os.path.join(self.tempdir, k), v) for k, v in files.iteritems())
    self.assertEqual(expected, actual)
    expected_stdout = (
        'To run this test please run from the directory %s:\n  Absurb command\n'
        % os.path.join(self.tempdir, 'a'))
    self.checkOutput(expected_stdout, '')

  def test_download_isolated_ar_archive(self):
    # Test downloading an isolated tree.
    actual = {}
    def putfile_mock(
        srcfileobj, dstpath, file_mode=None, size=-1, use_symlink=False):
      actual[dstpath] = srcfileobj.read(size)
    self.mock(isolateserver, 'putfile', putfile_mock)
    self.mock(os, 'makedirs', lambda _: None)
    server = 'http://example.com'

    files = {
      os.path.join('a', 'foo'): 'Content',
      'b': 'More content',
      'c': 'Even more content!',
    }

    archive = (
      # ar file header
      '!<arch>\n'
      # File 1 -------------------------
      # (16 bytes) filename len
      '#1/5            '
      # file metadata
      '1447140471  1000  1000  100640  '
      # (10 bytes) Data size
      '12        '
      # (2 bytes) File magic
      '\x60\n'
      # (5 bytes) File name
      'a/foo'
      # (7 bytes) File data
      'Content'
      # File 2 -------------------------
      # (16 bytes) filename
      'b               '
      # file metadata
      '1447140471  1000  1000  100640  '
      # (12 bytes) Data size
      '12        '
      # (2 bytes) File magic
      '\x60\n'
      # (12 bytes) File data
      'More content'
      '')

    isolated = {
      'command': ['Absurb', 'command'],
      'relative_cwd': 'a',
      'files': {
        'archive1': {
          'h': isolateserver_mock.hash_content(archive),
          's': len(archive),
          't': 'ar',
        },
        'c': {
          'h': isolateserver_mock.hash_content(files['c']),
          's': len(files['c']),
        },
      },
      'version': isolated_format.ISOLATED_FILE_VERSION,
    }
    isolated_data = json.dumps(isolated, sort_keys=True, separators=(',',':'))
    isolated_hash = isolateserver_mock.hash_content(isolated_data)
    requests = [
      (isolated['files']['archive1']['h'], archive),
      (isolated['files']['c']['h'], files['c']),
    ]
    requests.append((isolated_hash, isolated_data))
    requests = [
      (
        server + '/api/isolateservice/v1/retrieve',
        {
            'data': {
                'digest': h.encode('utf-8'),
                'namespace': {
                    'namespace': 'default-gzip',
                    'digest_hash': 'sha-1',
                    'compression': 'flate',
                },
                'offset': 0,
            },
            'read_timeout': 60,
        },
        {'content': base64.b64encode(zlib.compress(v))},
      ) for h, v in requests
    ]
    cmd = [
      'download',
      '--isolate-server', server,
      '--target', self.tempdir,
      '--isolated', isolated_hash,
    ]
    self.expected_requests(requests)
    self.assertEqual(0, isolateserver.main(cmd))
    expected = dict(
        (os.path.join(self.tempdir, k), v) for k, v in files.iteritems())
    self.assertEqual(expected, actual)
    expected_stdout = (
        'To run this test please run from the directory %s:\n  Absurb command\n'
        % os.path.join(self.tempdir, 'a'))
    self.checkOutput(expected_stdout, '')

  def test_download_isolated_tar_archive(self):
    # Test downloading an isolated tree.
    actual = {}
    def putfile_mock(
        srcfileobj, dstpath, file_mode=None, size=-1, use_symlink=False):
      actual[dstpath] = srcfileobj.read(size)
    self.mock(isolateserver, 'putfile', putfile_mock)
    self.mock(os, 'makedirs', lambda _: None)
    server = 'http://example.com'

    files = {
      os.path.join('a', 'foo'): 'Content',
      'b': 'More content',
      'c': 'Even more content!',
    }

    # Generate a tar archive
    tf = io.BytesIO()
    with tarfile.TarFile(mode='w', fileobj=tf) as tar:
      f1 = tarfile.TarInfo()
      f1.type = tarfile.REGTYPE
      f1.name = 'a/foo'
      f1.size = 7
      tar.addfile(f1, io.BytesIO('Content'))

      f2 = tarfile.TarInfo()
      f2.type = tarfile.REGTYPE
      f2.name = 'b'
      f2.size = 12
      tar.addfile(f2, io.BytesIO('More content'))
    archive = tf.getvalue()

    isolated = {
      'command': ['Absurb', 'command'],
      'relative_cwd': 'a',
      'files': {
        'archive1': {
          'h': isolateserver_mock.hash_content(archive),
          's': len(archive),
          't': 'tar',
        },
        'c': {
          'h': isolateserver_mock.hash_content(files['c']),
          's': len(files['c']),
        },
      },
      'version': isolated_format.ISOLATED_FILE_VERSION,
    }
    isolated_data = json.dumps(isolated, sort_keys=True, separators=(',',':'))
    isolated_hash = isolateserver_mock.hash_content(isolated_data)
    requests = [
      (isolated['files']['archive1']['h'], archive),
      (isolated['files']['c']['h'], files['c']),
    ]
    requests.append((isolated_hash, isolated_data))
    requests = [
      (
        server + '/api/isolateservice/v1/retrieve',
        {
            'data': {
                'digest': h.encode('utf-8'),
                'namespace': {
                    'namespace': 'default-gzip',
                    'digest_hash': 'sha-1',
                    'compression': 'flate',
                },
                'offset': 0,
            },
            'read_timeout': 60,
        },
        {'content': base64.b64encode(zlib.compress(v))},
      ) for h, v in requests
    ]
    cmd = [
      'download',
      '--isolate-server', server,
      '--target', self.tempdir,
      '--isolated', isolated_hash,
    ]
    self.expected_requests(requests)
    self.assertEqual(0, isolateserver.main(cmd))
    expected = dict(
        (os.path.join(self.tempdir, k), v) for k, v in files.iteritems())
    self.assertEqual(expected, actual)
    expected_stdout = (
        'To run this test please run from the directory %s:\n  Absurb command\n'
        % os.path.join(self.tempdir, 'a'))
    self.checkOutput(expected_stdout, '')


def get_storage(_isolate_server, namespace):
  class StorageFake(object):
    def __enter__(self, *_):
      return self

    def __exit__(self, *_):
      pass

    @property
    def hash_algo(self):  # pylint: disable=R0201
      return isolated_format.get_hash_algo(namespace)

    @staticmethod
    def upload_items(items):
      # Always returns the second item as not present.
      return [items[1]]
  return StorageFake()


class TestArchive(TestCase):
  @staticmethod
  def get_isolateserver_prog():
    """Returns 'isolateserver.py' or 'isolateserver.pyc'."""
    return os.path.basename(sys.modules[isolateserver.__name__].__file__)

  def test_archive_no_server(self):
    with self.assertRaises(SystemExit):
      isolateserver.main(['archive', '.'])
    prog = self.get_isolateserver_prog()
    self.checkOutput(
        '',
        'Usage: %(prog)s archive [options] <file1..fileN> or - to read '
        'from stdin\n\n'
        '%(prog)s: error: --isolate-server is required.\n' % {'prog': prog})

  def test_archive_duplicates(self):
    with self.assertRaises(SystemExit):
      isolateserver.main(
          [
            'archive', '--isolate-server', 'https://localhost:1',
            # Effective dupes.
            '.', os.getcwd(),
          ])
    prog = self.get_isolateserver_prog()
    self.checkOutput(
        '',
        'Usage: %(prog)s archive [options] <file1..fileN> or - to read '
        'from stdin\n\n'
        '%(prog)s: error: Duplicate entries found.\n' % {'prog': prog})

  def test_archive_files(self):
    self.mock(isolateserver, 'get_storage', get_storage)
    self.make_tree(CONTENTS)
    f = ['empty_file.txt', 'small_file.txt']
    os.chdir(self.tempdir)
    isolateserver.main(
        ['archive', '--isolate-server', 'https://localhost:1'] + f)
    self.checkOutput(
        'da39a3ee5e6b4b0d3255bfef95601890afd80709 empty_file.txt\n'
        '0491bd1da8087ad10fcdd7c9634e308804b72158 small_file.txt\n',
        '')

  def help_test_archive(self, cmd_line_prefix):
    self.mock(isolateserver, 'get_storage', get_storage)
    self.make_tree(CONTENTS)
    isolateserver.main(cmd_line_prefix + [self.tempdir])
    # If you modify isolated_format.ISOLATED_FILE_VERSION, you'll have to update
    # the hash below. Sorry about that but this ensures the .isolated format is
    # stable.
    isolated = {
      'algo': 'sha-1',
      'files': {},
      'version': isolated_format.ISOLATED_FILE_VERSION,
    }
    for k, v in CONTENTS.iteritems():
      isolated['files'][k] = {
        'h': isolateserver_mock.hash_content(v),
        's': len(v),
      }
      if sys.platform != 'win32':
        isolated['files'][k]['m'] = 0600
    isolated_data = json.dumps(isolated, sort_keys=True, separators=(',',':'))
    isolated_hash = isolateserver_mock.hash_content(isolated_data)
    self.checkOutput(
        '%s %s\n' % (isolated_hash, self.tempdir),
        '')

  def test_archive_directory(self):
    self.help_test_archive(['archive', '-I', 'https://localhost:1'])

  def test_archive_directory_envvar(self):
    with test_utils.EnvVars({'ISOLATE_SERVER': 'https://localhost:1'}):
      self.help_test_archive(['archive'])


class DiskCacheTest(TestCase):
  def setUp(self):
    super(DiskCacheTest, self).setUp()
    # If this fails on Windows, please rerun this tests as an elevated user with
    # administrator access right.
    self.assertEqual(True, file_path.enable_symlink())

    self._algo = isolated_format.get_hash_algo('default-gzip')
    self._free_disk = 1000
    # Max: 100 bytes, 2 items
    # Min free disk: 1000 bytes.
    self._policies = isolateserver.CachePolicies(100, 1000, 2)
    def get_free_space(p):
      self.assertEqual(p, self.tempdir)
      return self._free_disk
    self.mock(file_path, 'get_free_space', get_free_space)
    # TODO(maruel): Test the following.
    #cache.touch()

  def get_cache(self):
    return isolateserver.DiskCache(self.tempdir, self._policies, self._algo)

  def to_hash(self, content):
    return self._algo(content).hexdigest(), content

  def test_read_evict(self):
    self._free_disk = 1100
    h_a = self.to_hash('a')[0]
    with self.get_cache() as cache:
      cache.write(h_a, 'a')
      with cache.getfileobj(h_a) as f:
        self.assertEqual('a', f.read())

    with self.get_cache() as cache:
      cache.evict(h_a)
      with self.assertRaises(isolateserver.CacheMiss):
        cache.getfileobj(h_a)

  def test_policies_free_disk(self):
    with self.assertRaises(isolateserver.Error):
      self.get_cache().write(*self.to_hash('a'))

  def test_policies_fit(self):
    self._free_disk = 1100
    self.get_cache().write(*self.to_hash('a'*100))

  def test_policies_too_much(self):
    # Cache (size and # items) is not enforced while adding items but free disk
    # is.
    self._free_disk = 1004
    cache = self.get_cache()
    for i in ('a', 'b', 'c', 'd'):
      cache.write(*self.to_hash(i))
    # Mapping more content than the amount of free disk required.
    with self.assertRaises(isolateserver.Error):
      cache.write(*self.to_hash('e'))

  def test_cleanup(self):
    # Inject an item without a state.json. It will be deleted on cleanup.
    h_a = self.to_hash('a')[0]
    isolateserver.file_write(os.path.join(self.tempdir, h_a), 'a')
    cache = self.get_cache()
    self.assertEqual([], sorted(cache._lru._items.iteritems()))
    self.assertEqual(
        sorted([h_a, u'state.json']), sorted(os.listdir(self.tempdir)))
    cache.cleanup()
    self.assertEqual([u'state.json'], os.listdir(self.tempdir))

  def test_policies_active_trimming(self):
    # Start with a larger cache, add many object.
    # Reload the cache with smaller policies, the cache should be trimmed on
    # load.
    h_a = self.to_hash('a')[0]
    h_b = self.to_hash('b')[0]
    h_c = self.to_hash('c')[0]
    h_large, large = self.to_hash('b' * 99)

    def assertItems(expected):
      actual = [
        (digest, size) for digest, (size, _) in cache._lru._items.iteritems()]
      self.assertEqual(expected, actual)

    # Max policies is 100 bytes, 2 items, 1000 bytes free space.
    self._free_disk = 1101
    with self.get_cache() as cache:
      cache.write(h_a, 'a')
      cache.write(h_large, large)
      # Cache (size and # items) is not enforced while adding items. The
      # rationale is that a task may request more data than the size of the
      # cache policies. As long as there is free space, this is fine.
      cache.write(h_b, 'b')
      assertItems([(h_a, 1), (h_large, len(large)), (h_b, 1)])
      self.assertEqual(h_a, cache._protected)
      self.assertEqual(1000, cache._free_disk)
      self.assertEqual(0, cache.initial_number_items)
      self.assertEqual(0, cache.initial_size)
      # Free disk is enforced, because otherwise we assume the task wouldn't
      # be able to start. In this case, it throws an exception since all items
      # are protected. The item is added since it's detected after the fact.
      with self.assertRaises(isolateserver.Error):
        cache.write(h_c, 'c')

    # At this point, after the implicit trim in __exit__(), h_a and h_large were
    # evicted.
    self.assertEqual(
        sorted([h_b, h_c, u'state.json']), sorted(os.listdir(self.tempdir)))

    # Allow 3 items and 101 bytes so h_large is kept.
    self._policies = isolateserver.CachePolicies(101, 1000, 3)
    with self.get_cache() as cache:
      cache.write(h_large, large)
      self.assertEqual(2, cache.initial_number_items)
      self.assertEqual(2, cache.initial_size)

    self.assertEqual(
        sorted([h_b, h_c, h_large, u'state.json']),
        sorted(os.listdir(self.tempdir)))

    # Assert that trimming is done in constructor too.
    self._policies = isolateserver.CachePolicies(100, 1000, 2)
    with self.get_cache() as cache:
      assertItems([(h_c, 1), (h_large, len(large))])
      self.assertEqual(None, cache._protected)
      self.assertEqual(1101, cache._free_disk)
      self.assertEqual(2, cache.initial_number_items)
      self.assertEqual(100, cache.initial_size)

  def test_some_file_brutally_deleted(self):
    h_a = self.to_hash('a')[0]

    self._free_disk = 1100
    with self.get_cache() as cache:
      cache.write(h_a, 'a')
      self.assertTrue(cache.touch(h_a, isolateserver.UNKNOWN_FILE_SIZE))
      self.assertTrue(cache.touch(h_a, 1))

    os.remove(os.path.join(self.tempdir, h_a))

    with self.get_cache() as cache:
      # 'Ghost' entry loaded with state.json is still there.
      self.assertEqual({h_a}, cache.cached_set())
      # 'touch' detects the file is missing by returning False.
      self.assertFalse(cache.touch(h_a, isolateserver.UNKNOWN_FILE_SIZE))
      self.assertFalse(cache.touch(h_a, 1))
      # Evicting it still works, kills the 'ghost' entry.
      cache.evict(h_a)
      self.assertEqual(set(), cache.cached_set())


def clear_env_vars():
  for e in ('ISOLATE_DEBUG', 'ISOLATE_SERVER'):
    os.environ.pop(e, None)


if __name__ == '__main__':
  fix_encoding.fix_encoding()
  if '-v' in sys.argv:
    unittest.TestCase.maxDiff = None
  logging.basicConfig(
      level=(logging.DEBUG if '-v' in sys.argv else logging.CRITICAL))
  clear_env_vars()
  unittest.main()

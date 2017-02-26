#!/usr/bin/env python
# Copyright 2014 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import binascii
import time
import unittest
import sys

# Somehow this lets us find isolate_storage
import net_utils

from depot_tools import auto_stub
import isolate_storage
import test_utils


class FileServiceStubMock(object):
  """Replacement for real gRPC stub

  We can't mock *within* the real stub to replace individual functions, plus
  we'd have to mock __init__ every time anyway. So this class replaces the
  entire stub. As for the functions, they implement default happy path
  behaviour where possible, and are not implemented otherwise.
  """
  def __init__(self, _channel):
    self._push_requests = []
    self._contains_requests = []

  def FetchBlobs(self, request, timeout=None):
    raise NotImplementedError()

  def PushBlobs(self, requests):
    for r in requests:
      self._push_requests.append(r.__deepcopy__())
    response = isolate_storage.isolate_bot_pb2.PushBlobsReply()
    response.status.succeeded = True
    return response

  def Contains(self, request, timeout=None):
    del timeout
    response = isolate_storage.isolate_bot_pb2.ContainsReply()
    self._contains_requests.append(request.__deepcopy__())
    response.status.succeeded = True
    return response

  def popContainsRequests(self):
    cr = self._contains_requests
    self._contains_requests = []
    return cr

  def popPushRequests(self):
    pr = self._push_requests
    self._push_requests = []
    return pr


class IsolateStorageTest(auto_stub.TestCase):
  def get_server(self):
    return isolate_storage.IsolateServerGrpc('grpc-proxy.luci.com',
                                             'default-gzip')

  def testFetchHappySimple(self):
    """Fetch: if we get a few chunks with the right offset, everything works"""
    def FetchBlobs(self, request, timeout=None):
      del timeout
      self.request = request
      response = isolate_storage.isolate_bot_pb2.FetchBlobsReply()
      response.status.succeeded = True
      for i in range(0, 3):
        response.data.data = str(i)
        response.data.offset = i
        yield response
    self.mock(FileServiceStubMock, 'FetchBlobs', FetchBlobs)

    s = self.get_server()
    replies = s.fetch('abc123')
    response = replies.next()
    self.assertEqual(binascii.unhexlify('abc123'),
                     s._stub.request.digest[0].digest)
    self.assertEqual('0', response)
    response = replies.next()
    self.assertEqual('1', response)
    response = replies.next()
    self.assertEqual('2', response)

  def testFetchHappyZeroLengthBlob(self):
    """Fetch: if we get a zero-length blob, everything works"""
    def FetchBlobs(self, request, timeout=None):
      del timeout
      self.request = request
      response = isolate_storage.isolate_bot_pb2.FetchBlobsReply()
      response.status.succeeded = True
      response.data.data = ''
      yield response
    self.mock(FileServiceStubMock, 'FetchBlobs', FetchBlobs)

    s = self.get_server()
    replies = s.fetch('abc123')
    response = replies.next()
    self.assertEqual(binascii.unhexlify('abc123'),
                     s._stub.request.digest[0].digest)
    self.assertEqual(0, len(response))

  def testFetchThrowsOnWrongOffset(self):
    """Fetch: if we get a chunk with the wrong offset, we throw an exception"""
    def FetchBlobs(self, request, timeout=None):
      del timeout
      self.request = request
      response = isolate_storage.isolate_bot_pb2.FetchBlobsReply()
      response.status.succeeded = True
      response.data.data = str(42)
      response.data.offset = 1
      yield response
    self.mock(FileServiceStubMock, 'FetchBlobs', FetchBlobs)

    s = self.get_server()
    replies = s.fetch('abc123')
    with self.assertRaises(IOError):
      _response = replies.next()

  def testFetchThrowsOnFailure(self):
    """Fetch: if something goes wrong in Isolate, we throw an exception"""
    def FetchBlobs(self, request, timeout=None):
      del timeout
      self.request = request
      response = isolate_storage.isolate_bot_pb2.FetchBlobsReply()
      response.status.succeeded = False
      yield response
    self.mock(FileServiceStubMock, 'FetchBlobs', FetchBlobs)

    s = self.get_server()
    replies = s.fetch('abc123')
    with self.assertRaises(IOError):
      _response = replies.next()

  def testFetchThrowsCorrectExceptionOnGrpcFailure(self):
    """Fetch: if something goes wrong in gRPC, we throw an IOError"""
    def FetchBlobs(_self, _request, timeout=None):
      del timeout
      raise isolate_storage.grpc.RpcError('proxy died during initial fetch :(')
    self.mock(FileServiceStubMock, 'FetchBlobs', FetchBlobs)

    s = self.get_server()
    replies = s.fetch('abc123')
    with self.assertRaises(IOError):
      _response = replies.next()

  def testFetchThrowsCorrectExceptionOnStreamingGrpcFailure(self):
    """Fetch: if something goes wrong in gRPC, we throw an IOError"""
    def FetchBlobs(self, request, timeout=None):
      del timeout
      self.request = request
      response = isolate_storage.isolate_bot_pb2.FetchBlobsReply()
      response.status.succeeded = True
      for i in range(0, 3):
        if i is 2:
          raise isolate_storage.grpc.RpcError(
              'proxy died during fetch stream :(')
        response.data.data = str(i)
        response.data.offset = i
        yield response
    self.mock(FileServiceStubMock, 'FetchBlobs', FetchBlobs)

    s = self.get_server()
    with self.assertRaises(IOError):
      for _response in s.fetch('abc123'):
        pass

  def testPushHappySingleSmall(self):
    """Push: send one chunk of small data"""
    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=4)
    s.push(i, isolate_storage._IsolateServerGrpcPushState(), '1234')
    requests = s._stub.popPushRequests()
    self.assertEqual(1, len(requests))
    self.assertEqual(binascii.unhexlify('abc123'),
                     requests[0].data.digest.digest)
    self.assertEqual(4, requests[0].data.digest.size_bytes)
    self.assertEqual('1234', requests[0].data.data)

  def testPushHappySingleBig(self):
    """Push: send one chunk of big data by splitting it into two"""
    self.mock(isolate_storage, 'NET_IO_FILE_CHUNK', 3)
    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=4)
    s.push(i, isolate_storage._IsolateServerGrpcPushState(), '1234')
    requests = s._stub.popPushRequests()
    self.assertEqual(2, len(requests))
    self.assertEqual(binascii.unhexlify('abc123'),
                     requests[0].data.digest.digest)
    self.assertEqual(4, requests[0].data.digest.size_bytes)
    self.assertEqual('123', requests[0].data.data)
    self.assertFalse(requests[1].data.HasField('digest'))
    self.assertEqual('4', requests[1].data.data)

  def testPushHappyMultiSmall(self):
    """Push: sends multiple small chunks"""
    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=4)
    s.push(i, isolate_storage._IsolateServerGrpcPushState(), ['12', '34'])
    requests = s._stub.popPushRequests()
    self.assertEqual(2, len(requests))
    self.assertEqual(binascii.unhexlify('abc123'),
                     requests[0].data.digest.digest)
    self.assertEqual(4, requests[0].data.digest.size_bytes)
    self.assertEqual('12', requests[0].data.data)
    self.assertFalse(requests[1].data.HasField('digest'))
    self.assertEqual('34', requests[1].data.data)

  def testPushHappyMultiBig(self):
    """Push: sends multiple chunks, each of which have to be split"""
    self.mock(isolate_storage, 'NET_IO_FILE_CHUNK', 2)
    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=6)
    s.push(i, isolate_storage._IsolateServerGrpcPushState(), ['123', '456'])
    requests = s._stub.popPushRequests()
    self.assertEqual(4, len(requests))
    self.assertEqual(binascii.unhexlify('abc123'),
                     requests[0].data.digest.digest)
    self.assertEqual(6, requests[0].data.digest.size_bytes)
    self.assertEqual('12', requests[0].data.data)
    self.assertFalse(requests[1].data.HasField('digest'))
    self.assertEqual('3', requests[1].data.data)
    self.assertEqual('45', requests[2].data.data)
    self.assertEqual('6', requests[3].data.data)

  def testPushHappyZeroLengthBlob(self):
    """Push: send a zero-length blob"""
    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=0)
    s.push(i, isolate_storage._IsolateServerGrpcPushState(), '')
    requests = s._stub.popPushRequests()
    self.assertEqual(1, len(requests))
    self.assertEqual(binascii.unhexlify('abc123'),
                     requests[0].data.digest.digest)
    self.assertEqual(0, requests[0].data.digest.size_bytes)
    self.assertEqual('', requests[0].data.data)

  def testPushThrowsOnFailure(self):
    """Push: if something goes wrong in Isolate, we throw an exception"""
    def PushBlobs(self, request, timeout=None):
      del request, timeout, self
      response = isolate_storage.isolate_bot_pb2.PushBlobsReply()
      response.status.succeeded = False
      return response
    self.mock(FileServiceStubMock, 'PushBlobs', PushBlobs)

    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=0)
    with self.assertRaises(IOError):
      s.push(i, isolate_storage._IsolateServerGrpcPushState(), '1234')

  def testPushThrowsCorrectExceptionOnGrpcFailure(self):
    """Push: if something goes wrong in Isolate, we throw an exception"""
    def PushBlobs(_self, _request, timeout=None):
      del timeout
      raise isolate_storage.grpc.RpcError('proxy died during push :(')
    self.mock(FileServiceStubMock, 'PushBlobs', PushBlobs)

    s = self.get_server()
    i = isolate_storage.Item(digest='abc123', size=0)
    with self.assertRaises(IOError):
      s.push(i, isolate_storage._IsolateServerGrpcPushState(), '1234')

  def testContainsHappySimple(self):
    """Contains: basic sanity check"""
    items = []
    for i in range(0, 3):
      digest = ''.join(['a', str(i)])
      i = isolate_storage.Item(digest=digest, size=1)
      items.append(i)
    s = self.get_server()
    response = s.contains(items)
    self.assertEqual(0, len(response))
    requests = s._stub.popContainsRequests()
    self.assertEqual(3, len(requests[0].digest))
    self.assertEqual('\xa0', requests[0].digest[0].digest)
    self.assertEqual('\xa1', requests[0].digest[1].digest)
    self.assertEqual('\xa2', requests[0].digest[2].digest)

  def testContainsMissingSimple(self):
    """Contains: the digests are missing"""
    def Contains(self, request, timeout=None):
      del timeout, self
      response = isolate_storage.isolate_bot_pb2.ContainsReply()
      response.status.succeeded = False
      response.status.error = (
          isolate_storage.isolate_bot_pb2.BlobStatus.MISSING_DIGEST)
      for d in request.digest:
        msg = response.status.missing_digest.add()
        msg.CopyFrom(d)
      return response
    self.mock(FileServiceStubMock, 'Contains', Contains)

    items = []
    for i in range(0, 3):
      digest = ''.join(['a', str(i)])
      i = isolate_storage.Item(digest=digest, size=1)
      items.append(i)
    s = self.get_server()
    response = s.contains(items)
    self.assertEqual(3, len(response))
    self.assertTrue(items[0] in response)
    self.assertTrue(items[1] in response)
    self.assertTrue(items[2] in response)

  def testContainsThrowsCorrectExceptionOnGrpcFailure(self):
    """Contains: the digests are missing"""
    def Contains(_self, _request, timeout=None):
      del timeout
      raise isolate_storage.grpc.RpcError('proxy died during contains :(')
    self.mock(FileServiceStubMock, 'Contains', Contains)

    items = []
    for i in range(0, 3):
      digest = ''.join(['a', str(i)])
      i = isolate_storage.Item(digest=digest, size=1)
      items.append(i)
    s = self.get_server()
    with self.assertRaises(IOError):
      _response = s.contains(items)


if __name__ == '__main__':
  if not isolate_storage.grpc:
    # Don't print to stderr or return error code as this will
    # show up as a warning and fail in presubmit.
    print('gRPC could not be loaded; skipping tests')
    sys.exit(0)
  isolate_storage.isolate_bot_pb2.FileServiceStub = FileServiceStubMock
  test_utils.main()

# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""This file defines the entry point for most external consumers of the Python
Codesearch library.
"""

from __future__ import absolute_import

import logging
import os

from .file_cache import FileCache
from .messages import CompoundRequest, AnnotationType, AnnotationTypeValue, \
        CompoundResponse, FileInfoRequest, FileSpec, AnnotationRequest, \
        EdgeEnumKind, XrefSearchRequest
from .paths import GetSourceRoot

try:
  from urllib.request import urlopen
  from urllib.parse import urlencode
except ImportError:
  from urllib2 import urlopen
  from urllib import urlencode


class CodeSearch(object):

  def __init__(self,
               should_cache=False,
               cache_dir=None,
               a_path_inside_source_dir=None,
               package_name='chromium',
               codesearch_host='https://cs.chromium.org',
               request_timeout_in_seconds=3):

    self.file_cache = None

    self.logger = logging.getLogger('codesearch')

    self.source_root = ''

    self.package_name = package_name

    self.codesearch_host = codesearch_host

    self.request_timeout_in_seconds = request_timeout_in_seconds

    self.source_root = GetSourceRoot(a_path_inside_source_dir)

    if not should_cache:
      self.file_cache = None
      return
    if self.file_cache:
      return
    self.file_cache = FileCache(cache_dir=cache_dir)

  def GetSourceRoot(self):
    return self.source_root

  def GetLogger(self):
    return self.logger

  def GetFileSpec(self, path=None):
    if not path:
      return FileSpec(name='.', package_name=self.package_name)

    return FileSpec(
        name=os.path.relpath(os.path.abspath(path), self.source_root),
        package_name=self.package_name)

  def TeardownCache(self):
    if self.file_cache:
      self.file_cache.close()

    self.file_cache = None
    self.source_root = None

  def _Retrieve(self, url):
    """Retrieve the URL by first checking the cache and then falling back to
        using the network."""
    self.logger.debug('Fetching %s', url)

    if self.file_cache:
      cached_response = self.file_cache.get(url)
      self.logger.debug('Found cached response')
      if (cached_response):
        return cached_response.decode('utf8')
    response = urlopen(url, timeout=self.request_timeout_in_seconds)
    result = response.read()
    if self.file_cache:
      self.file_cache.put(url, result)
    return result.decode('utf8')

  def SendRequestToServer(self, compound_request):
    if not isinstance(compound_request, CompoundRequest):
      raise ValueError(
          '|compound_request| should be an instance of CompoundRequest')

    qs = urlencode(compound_request.AsQueryString(), doseq=True)
    url = '{host}/codesearch/json?{qs}'.format(host=self.codesearch_host, qs=qs)
    result = self._Retrieve(url)
    return CompoundResponse.FromJsonString(result)

  def GetAnnotationsForFile(self, filename, annotation_types):
    return self.SendRequestToServer(
        CompoundRequest(annotation_request=[
            AnnotationRequest(
                file_spec=self.GetFileSpec(filename), type=annotation_types)
        ]))

  def GetSignatureForLocation(self, filename, line, column):
    result = self.GetAnnotationsForFile(
        filename, [AnnotationType(id=AnnotationTypeValue.XREF_SIGNATURE)])
    result = result.annotation_response[0]

    if result.return_code != 1:
      raise Exception('Request failed. Response=%s' % (result.AsQueryString()))

    for annotation in result.annotation:
      if not annotation.range.Contains(line, column):
        continue

      if hasattr(annotation, 'xref_signature'):
        return annotation.xref_signature.signature

      if hasattr(annotation, 'internal_link'):
        return annotation.internal_link.signature

    raise Exception("Can't determine signature for %s at %d:%d" %
                    (filename, line, column))

  def GetSignatureForSymbol(self, filename, symbol):
    result = self.GetAnnotationsForFile(
        filename, [AnnotationType(id=AnnotationTypeValue.XREF_SIGNATURE)])
    result = result.annotation_response[0]

    if result.return_code != 1:
      raise Exception('Request failed. Response=%s' % (result.AsQueryString()))

    for snippet in result.annotation:
      if hasattr(snippet, 'xref_signature'):
        signature = snippet.xref_signature.signature
        if '%s(' % symbol in signature:
          return signature

      elif hasattr(snippet, 'internal_link'):
        signature = snippet.internal_link.signature
        if '::%s' % symbol in signature or 'class-%s' % symbol in signature:
          return signature

    raise Exception("Can't determine signature for %s:%s" % (filename, symbol))

  def GetXrefsFor(self, signature, edge_filter):
    refs = self.SendRequestToServer(
        CompoundRequest(xref_search_request=[
            XrefSearchRequest(
                file_spec=self.GetFileSpec(),
                query=signature,
                edge_filter=edge_filter)
        ]))
    if not refs or not hasattr(refs.xref_search_response[0], 'search_result'):
      return []
    return refs.xref_search_response[0].search_result

  def GetOverridingDefinitions(self, signature):
    candidates = []
    refs = self.GetXrefsFor(signature, [EdgeEnumKind.OVERRIDDEN_BY])
    for result in refs:
      matches = []
      for match in result.match:
        if hasattr(match, 'grok_modifiers') and hasattr(
            match.grok_modifiers,
            'definition') and match.grok_modifiers.definition:
          matches.append(match)
      if matches:
        result.match = matches
        candidates.append(result)
    return candidates

  def GetCallTargets(self, signature):
    # First look up the declaration for the callsite.
    refs = self.GetXrefsFor(signature, [EdgeEnumKind.HAS_DECLARATION])

    candidates = []
    for result in refs:
      for match in result.match:
        if hasattr(match, 'grok_modifiers') and hasattr(
            match.grok_modifiers, 'virtual') and match.grok_modifiers.virtual:
          candidates.extend(self.GetOverridingDefinitions(match.signature))
    if not candidates:
      return self.GetXrefsFor(signature, [EdgeEnumKind.HAS_DEFINITION])
    return candidates

  def IsContentStale(self, filename, buffer_lines, check_prefix=False):
    response = self.SendRequestToServer(
        CompoundRequest(file_info_request=[
            FileInfoRequest(
                file_spec=self.GetFileSpec(filename),
                fetch_html_content=False,
                fetch_outline=False,
                fetch_folding=False,
                fetch_generated_from=False)
        ]))

    response = response.file_info_response[0]
    content_lines = response.file_info.content.text.split('\n')

    if check_prefix:
      content_lines = content_lines[:len(buffer_lines)]
      if len(content_lines) != len(buffer_lines):
        return True

    for left, right in zip(content_lines, buffer_lines):
      if left != right:
        return True

    return False

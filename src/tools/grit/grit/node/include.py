#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Handling of the <include> element.
"""

import os
import sys

from grit import exception
from grit import util
import grit.format.gzip_string
import grit.format.html_inline
import grit.format.rc
import grit.format.rc_header
from grit.format import minifier
from grit.node import base

class IncludeNode(base.Node):
  """An <include> element."""

  def __init__(self):
    super(IncludeNode, self).__init__()

    # Cache flattened data so that we don't flatten the same file
    # multiple times.
    self._flattened_data = None
    # Also keep track of the last filename we flattened to, so we can
    # avoid doing it more than once.
    self._last_flat_filename = None

  def _IsValidChild(self, child):
    return False

  def _GetFlattenedData(self, allow_external_script=False):
    if not self._flattened_data:
      filename = self.ToRealPath(self.GetInputPath())
      self._flattened_data = (
          grit.format.html_inline.InlineToString(filename, self,
              preprocess_only=False,
              allow_external_script=allow_external_script))
    return self._flattened_data
  def MandatoryAttributes(self):
    return ['name', 'type', 'file']

  def DefaultAttributes(self):
    return {'translateable' : 'true',
            'generateid': 'true',
            'filenameonly': 'false',
            'mkoutput': 'false',
            'flattenhtml': 'false',
            'compress': 'false',
            'allowexternalscript': 'false',
            'relativepath': 'false',
            'use_base_dir': 'true',
           }

  def GetInputPath(self):
    # Do not mess with absolute paths, that would make them invalid.
    if os.path.isabs(os.path.expandvars(self.attrs['file'])):
      return self.attrs['file']

    # We have no control over code that calles ToRealPath later, so convert
    # the path to be relative against our basedir.
    if self.attrs.get('use_base_dir', 'true') != 'true':
      return os.path.relpath(self.attrs['file'], self.GetRoot().GetBaseDir())

    return self.attrs['file']

  def FileForLanguage(self, lang, output_dir):
    """Returns the file for the specified language.  This allows us to return
    different files for different language variants of the include file.
    """
    input_path = self.GetInputPath()
    if input_path is None:
      return None

    return self.ToRealPath(input_path)

  def GetDataPackPair(self, lang, encoding):
    """Returns a (id, string) pair that represents the resource id and raw
    bytes of the data.  This is used to generate the data pack data file.
    """
    # TODO(benrg/joi): Move this and other implementations of GetDataPackPair
    # to grit.format.data_pack?
    from grit.format import rc_header
    id_map = rc_header.GetIds(self.GetRoot())
    id = id_map[self.GetTextualIds()[0]]
    filename = self.ToRealPath(self.GetInputPath())
    if self.attrs['flattenhtml'] == 'true':
      allow_external_script = self.attrs['allowexternalscript'] == 'true'
      data = self._GetFlattenedData(allow_external_script=allow_external_script)
    else:
      data = util.ReadFile(filename, util.BINARY)
    # Note that the minifier will only do anything if a minifier command
    # has been set in the command line.
    data = minifier.Minify(data, os.path.splitext(filename)[1])
    if 'compress' in self.attrs and self.attrs['compress'] == 'gzip':
      # We only use rsyncable compression on Linux.
      # We exclude ChromeOS since ChromeOS bots are Linux based but do not have
      # the --rsyncable option built in for gzip. See crbug.com/617950.
      if sys.platform == 'linux2' and 'chromeos' not in self.GetRoot().defines:
        data = grit.format.gzip_string.GzipStringRsyncable(data)
      else:
        data = grit.format.gzip_string.GzipString(data)

    # Include does not care about the encoding, because it only returns binary
    # data.
    return id, data

  def Process(self, output_dir):
    """Rewrite file references to be base64 encoded data URLs.  The new file
    will be written to output_dir and the name of the new file is returned."""
    filename = self.ToRealPath(self.GetInputPath())
    flat_filename = os.path.join(output_dir,
        self.attrs['name'] + '_' + os.path.basename(filename))

    if self._last_flat_filename == flat_filename:
      return

    with open(flat_filename, 'wb') as outfile:
      outfile.write(self._GetFlattenedData())

    self._last_flat_filename = flat_filename
    return os.path.basename(flat_filename)

  def GetHtmlResourceFilenames(self):
    """Returns a set of all filenames inlined by this file."""
    allow_external_script = self.attrs['allowexternalscript'] == 'true'
    return grit.format.html_inline.GetResourceFilenames(
         self.ToRealPath(self.GetInputPath()),
         allow_external_script=allow_external_script)

  def IsResourceMapSource(self):
    return True

  def GeneratesResourceMapEntry(self, output_all_resource_defines,
                                is_active_descendant):
    # includes always generate resource entries.
    if output_all_resource_defines:
      return True
    return is_active_descendant

  @staticmethod
  def Construct(parent, name, type, file, translateable=True,
                filenameonly=False, mkoutput=False, relativepath=False):
    """Creates a new node which is a child of 'parent', with attributes set
    by parameters of the same name.
    """
    # Convert types to appropriate strings
    translateable = util.BoolToString(translateable)
    filenameonly = util.BoolToString(filenameonly)
    mkoutput = util.BoolToString(mkoutput)
    relativepath = util.BoolToString(relativepath)

    node = IncludeNode()
    node.StartParsing('include', parent)
    node.HandleAttribute('name', name)
    node.HandleAttribute('type', type)
    node.HandleAttribute('file', file)
    node.HandleAttribute('translateable', translateable)
    node.HandleAttribute('filenameonly', filenameonly)
    node.HandleAttribute('mkoutput', mkoutput)
    node.HandleAttribute('relativepath', relativepath)
    node.EndParsing()
    return node

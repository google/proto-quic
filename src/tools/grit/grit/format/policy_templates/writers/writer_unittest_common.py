#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Common tools for unit-testing writers.'''


import os
import tempfile
import unittest
import StringIO

from grit import grd_reader
from grit import util
from grit.tool import build


class DummyOutput(object):
  def __init__(self, type, language, file = 'hello.gif'):
    self.type = type
    self.language = language
    self.file = file
  def GetType(self):
    return self.type
  def GetLanguage(self):
    return self.language
  def GetOutputFilename(self):
    return self.file


class WriterUnittestCommon(unittest.TestCase):
  '''Common class for unittesting writers.'''

  def PrepareTest(self, policy_json):
    '''Prepares and parses a grit tree along with a data structure of policies.

    Args:
      policy_json: The policy data structure in JSON format.
    '''
    # First create a temporary file that contains the JSON policy list.
    tmp_file_name = 'test.json'
    tmp_dir_name = tempfile.gettempdir()
    json_file_path = tmp_dir_name + '/' + tmp_file_name
    with open(json_file_path, 'w') as f:
      f.write(policy_json.strip())
    # Then assemble the grit tree.
    grd_text = '''
    <grit base_dir="." latest_public_release="0" current_release="1" source_lang_id="en">
      <release seq="1">
        <structures>
          <structure name="IDD_POLICY_SOURCE_FILE" file="%s" type="policy_template_metafile" />
        </structures>
      </release>
    </grit>''' % json_file_path
    grd_string_io = StringIO.StringIO(grd_text)
    # Parse the grit tree and load the policies' JSON with a gatherer.
    grd = grd_reader.Parse(grd_string_io, dir=tmp_dir_name)
    grd.SetOutputLanguage('en')
    grd.RunGatherers()
    # Remove the policies' JSON.
    os.unlink(json_file_path)
    return grd

  def GetOutput(self, grd, env_lang, env_defs, out_type, out_lang):
    '''Generates an output of a writer.

    Args:
      grd: The root of the grit tree.
      env_lang: The environment language.
      env_defs: Environment definitions.
      out_type: Type of the output node for which output will be generated.
        This selects the writer.
      out_lang: Language of the output node for which output will be generated.

    Returns:
      The string of the template created by the writer.
    '''
    grd.SetOutputLanguage(env_lang)
    grd.SetDefines(env_defs)
    buf = StringIO.StringIO()
    build.RcBuilder.ProcessNode(grd, DummyOutput(out_type, out_lang), buf)
    return buf.getvalue()

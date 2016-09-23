#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.resource_map'''

import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

import StringIO
import unittest

from grit import grd_reader
from grit import util
from grit.format import resource_map


class FormatResourceMapUnittest(unittest.TestCase):
  def testFormatResourceMap(self):
    grd = grd_reader.Parse(StringIO.StringIO(
      '''<?xml version="1.0" encoding="UTF-8"?>
      <grit latest_public_release="2" source_lang_id="en" current_release="3"
            base_dir=".">
        <outputs>
          <output type="rc_header" filename="the_rc_header.h" />
          <output type="resource_map_header"
                  filename="the_resource_map_header.h" />
        </outputs>
        <release seq="3">
          <structures first_id="300">
            <structure type="menu" name="IDC_KLONKMENU"
                       file="grit\\testdata\\klonk.rc" encoding="utf-16" />
          </structures>
          <includes first_id="10000">
            <include type="foo" file="abc" name="IDS_FIRSTPRESENT" />
            <if expr="False">
              <include type="foo" file="def" name="IDS_MISSING" />
            </if>
            <if expr="lang != 'es'">
              <include type="foo" file="ghi" name="IDS_LANGUAGESPECIFIC" />
            </if>
            <if expr="lang == 'es'">
              <include type="foo" file="jkl" name="IDS_LANGUAGESPECIFIC" />
            </if>
            <include type="foo" file="mno" name="IDS_THIRDPRESENT" />
         </includes>
        </release>
      </grit>'''), util.PathFromRoot('.'))
    grd.SetOutputLanguage('en')
    grd.RunGatherers()
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_header')(grd, 'en', '.')))
    self.assertEqual('''\
#include <stddef.h>
#ifndef GRIT_RESOURCE_MAP_STRUCT_
#define GRIT_RESOURCE_MAP_STRUCT_
struct GritResourceMap {
  const char* const name;
  int value;
};
#endif // GRIT_RESOURCE_MAP_STRUCT_
extern const GritResourceMap kTheRcHeader[];
extern const size_t kTheRcHeaderSize;''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_resource_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"IDC_KLONKMENU", IDC_KLONKMENU},
  {"IDS_FIRSTPRESENT", IDS_FIRSTPRESENT},
  {"IDS_MISSING", IDS_MISSING},
  {"IDS_LANGUAGESPECIFIC", IDS_LANGUAGESPECIFIC},
  {"IDS_THIRDPRESENT", IDS_THIRDPRESENT},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_file_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_resource_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"grit/testdata/klonk.rc", IDC_KLONKMENU},
  {"abc", IDS_FIRSTPRESENT},
  {"def", IDS_MISSING},
  {"ghi", IDS_LANGUAGESPECIFIC},
  {"jkl", IDS_LANGUAGESPECIFIC},
  {"mno", IDS_THIRDPRESENT},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)

  def testFormatResourceMapWithOutputAllEqualsFalseForStructures(self):
    grd = grd_reader.Parse(StringIO.StringIO(
      '''<?xml version="1.0" encoding="UTF-8"?>
      <grit latest_public_release="2" source_lang_id="en" current_release="3"
            base_dir="." output_all_resource_defines="false">
        <outputs>
          <output type="rc_header" filename="the_rc_header.h" />
          <output type="resource_map_header"
                  filename="the_resource_map_header.h" />
          <output type="resource_map_source"
                  filename="the_resource_map_header.cc" />
        </outputs>
        <release seq="3">
          <structures first_id="300">
            <structure type="chrome_scaled_image" name="IDR_KLONKMENU"
                       file="foo.png" />
            <if expr="False">
              <structure type="chrome_scaled_image" name="IDR_MISSING"
                         file="bar.png" />
            </if>
            <if expr="True">
              <structure type="chrome_scaled_image" name="IDR_BLOB"
                         file="blob.png" />
            </if>
            <if expr="True">
              <then>
                <structure type="chrome_scaled_image" name="IDR_METEOR"
                           file="meteor.png" />
              </then>
              <else>
                <structure type="chrome_scaled_image" name="IDR_METEOR"
                           file="roetem.png" />
              </else>
            </if>
            <if expr="False">
              <structure type="chrome_scaled_image" name="IDR_LAST"
                         file="zyx.png" />
            </if>
            <if expr="True">
              <structure type="chrome_scaled_image" name="IDR_LAST"
                         file="xyz.png" />
            </if>
         </structures>
        </release>
      </grit>'''), util.PathFromRoot('.'))
    grd.SetOutputLanguage('en')
    grd.RunGatherers()
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_header')(grd, 'en', '.')))
    self.assertEqual('''\
#include <stddef.h>
#ifndef GRIT_RESOURCE_MAP_STRUCT_
#define GRIT_RESOURCE_MAP_STRUCT_
struct GritResourceMap {
  const char* const name;
  int value;
};
#endif // GRIT_RESOURCE_MAP_STRUCT_
extern const GritResourceMap kTheRcHeader[];
extern const size_t kTheRcHeaderSize;''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_resource_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"IDR_KLONKMENU", IDR_KLONKMENU},
  {"IDR_BLOB", IDR_BLOB},
  {"IDR_METEOR", IDR_METEOR},
  {"IDR_LAST", IDR_LAST},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_resource_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"IDR_KLONKMENU", IDR_KLONKMENU},
  {"IDR_BLOB", IDR_BLOB},
  {"IDR_METEOR", IDR_METEOR},
  {"IDR_LAST", IDR_LAST},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)

  def testFormatResourceMapWithOutputAllEqualsFalseForIncludes(self):
    grd = grd_reader.Parse(StringIO.StringIO(
      '''<?xml version="1.0" encoding="UTF-8"?>
      <grit latest_public_release="2" source_lang_id="en" current_release="3"
            base_dir="." output_all_resource_defines="false">
        <outputs>
          <output type="rc_header" filename="the_rc_header.h" />
          <output type="resource_map_header"
                  filename="the_resource_map_header.h" />
        </outputs>
        <release seq="3">
          <structures first_id="300">
            <structure type="menu" name="IDC_KLONKMENU"
                       file="grit\\testdata\\klonk.rc" encoding="utf-16" />
          </structures>
          <includes first_id="10000">
            <include type="foo" file="abc" name="IDS_FIRSTPRESENT" />
            <if expr="False">
              <include type="foo" file="def" name="IDS_MISSING" />
            </if>
            <include type="foo" file="mno" name="IDS_THIRDPRESENT" />
            <if expr="True">
              <include type="foo" file="blob" name="IDS_BLOB" />
            </if>
            <if expr="True">
              <then>
                <include type="foo" file="meteor" name="IDS_METEOR" />
              </then>
              <else>
                <include type="foo" file="roetem" name="IDS_METEOR" />
              </else>
            </if>
            <if expr="False">
              <include type="foo" file="zyx" name="IDS_LAST" />
            </if>
            <if expr="True">
              <include type="foo" file="xyz" name="IDS_LAST" />
            </if>
         </includes>
        </release>
      </grit>'''), util.PathFromRoot('.'))
    grd.SetOutputLanguage('en')
    grd.RunGatherers()
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_header')(grd, 'en', '.')))
    self.assertEqual('''\
#include <stddef.h>
#ifndef GRIT_RESOURCE_MAP_STRUCT_
#define GRIT_RESOURCE_MAP_STRUCT_
struct GritResourceMap {
  const char* const name;
  int value;
};
#endif // GRIT_RESOURCE_MAP_STRUCT_
extern const GritResourceMap kTheRcHeader[];
extern const size_t kTheRcHeaderSize;''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_resource_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"IDC_KLONKMENU", IDC_KLONKMENU},
  {"IDS_FIRSTPRESENT", IDS_FIRSTPRESENT},
  {"IDS_THIRDPRESENT", IDS_THIRDPRESENT},
  {"IDS_BLOB", IDS_BLOB},
  {"IDS_METEOR", IDS_METEOR},
  {"IDS_LAST", IDS_LAST},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_file_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_resource_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"grit/testdata/klonk.rc", IDC_KLONKMENU},
  {"abc", IDS_FIRSTPRESENT},
  {"mno", IDS_THIRDPRESENT},
  {"blob", IDS_BLOB},
  {"meteor", IDS_METEOR},
  {"xyz", IDS_LAST},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)

  def testFormatStringResourceMap(self):
    grd = grd_reader.Parse(StringIO.StringIO(
      '''<?xml version="1.0" encoding="UTF-8"?>
      <grit latest_public_release="2" source_lang_id="en" current_release="3"
            base_dir=".">
        <outputs>
          <output type="rc_header" filename="the_rc_header.h" />
          <output type="resource_map_header" filename="the_rc_map_header.h" />
          <output type="resource_map_source" filename="the_rc_map_source.cc" />
        </outputs>
        <release seq="1" allow_pseudo="false">
          <messages fallback_to_english="true">
            <message name="IDS_PRODUCT_NAME" desc="The application name">
              Application
            </message>
            <if expr="True">
              <message name="IDS_DEFAULT_TAB_TITLE_TITLE_CASE"
                  desc="In Title Case: The default title in a tab.">
                New Tab
              </message>
            </if>
            <if expr="False">
              <message name="IDS_DEFAULT_TAB_TITLE"
                  desc="The default title in a tab.">
                New tab
              </message>
            </if>
          </messages>
        </release>
      </grit>'''), util.PathFromRoot('.'))
    grd.SetOutputLanguage('en')
    grd.RunGatherers()
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_header')(grd, 'en', '.')))
    self.assertEqual('''\
#include <stddef.h>
#ifndef GRIT_RESOURCE_MAP_STRUCT_
#define GRIT_RESOURCE_MAP_STRUCT_
struct GritResourceMap {
  const char* const name;
  int value;
};
#endif // GRIT_RESOURCE_MAP_STRUCT_
extern const GritResourceMap kTheRcHeader[];
extern const size_t kTheRcHeaderSize;''', output)
    output = util.StripBlankLinesAndComments(''.join(
        resource_map.GetFormatter('resource_map_source')(grd, 'en', '.')))
    self.assertEqual('''\
#include "the_rc_map_header.h"
#include <stddef.h>
#include "base/macros.h"
#include "the_rc_header.h"
const GritResourceMap kTheRcHeader[] = {
  {"IDS_PRODUCT_NAME", IDS_PRODUCT_NAME},
  {"IDS_DEFAULT_TAB_TITLE_TITLE_CASE", IDS_DEFAULT_TAB_TITLE_TITLE_CASE},
};
const size_t kTheRcHeaderSize = arraysize(kTheRcHeader);''', output)


if __name__ == '__main__':
  unittest.main()

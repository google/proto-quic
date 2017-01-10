# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import unittest

import checkteamtags

SRC = os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)
sys.path.append(os.path.join(SRC, 'third_party', 'pymock'))

import mock


def mock_file(lines):
  inner_mock = mock.MagicMock()
  inner_attrs = {'readlines.return_value': lines}
  inner_mock.configure_mock(**inner_attrs)

  return_val = mock.MagicMock()
  attrs = {'__enter__.return_value': inner_mock}
  return_val.configure_mock(**attrs)
  return return_val

NO_TAGS = """
mock@chromium.org
""".splitlines()

MULTIPLE_COMPONENT_TAGS = """
mock@chromium.org

# COMPONENT: Blink>mock_component
# COMPONENT: V8>mock_component
""".splitlines()

MULTIPLE_COMPONENTS_IN_TAG = """
mock@chromium.org

# COMPONENT: Blink>mock_component, V8>mock_component
""".splitlines()

MISSING_COMPONENT = """
mock@chromium.org

# COMPONENT:
""".splitlines()

MULTIPLE_TEAM_TAGS = """
mock@chromium.org

# TEAM: some-team@chromium.org
# TEAM: some-other-team@chromium.org
""".splitlines()

MULTIPLE_TEAMS_IN_TAG = """
mock@chromium.org

# TEAM: some-team@chromium.org some-other-team@chromium.org
""".splitlines()

MISSING_TEAM = """
mock@chromium.org

# TEAM:
""".splitlines()

BASIC = """
mock@chromium.org

# TEAM: some-team@chromium.org
# COMPONENT: V8>mock_component
""".splitlines()

open_name = 'checkteamtags.open'

@mock.patch('sys.argv', ['checkteamtags', '--bare' ,'OWNERS'])
@mock.patch('sys.stdout', mock.MagicMock())
class CheckTeamTagsTest(unittest.TestCase):
  def testNoTags(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(NO_TAGS)
      self.assertEqual(0, checkteamtags.main())

  def testMultipleComponentTags(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(MULTIPLE_COMPONENT_TAGS)
      self.assertEqual(1, checkteamtags.main())

  def testMultipleComponentsInTag(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(MULTIPLE_COMPONENTS_IN_TAG)
      self.assertEqual(1, checkteamtags.main())

  def testMissingComponent(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(MISSING_COMPONENT)
      self.assertEqual(1, checkteamtags.main())

  def testMultipleTeamTags(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(MULTIPLE_TEAM_TAGS)
      self.assertEqual(1, checkteamtags.main())

  def testMultipleTeamsInTag(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(MULTIPLE_TEAMS_IN_TAG)
      self.assertEqual(1, checkteamtags.main())

  def testMissingTeam(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(MISSING_TEAM)
      self.assertEqual(1, checkteamtags.main())

  def testBasic(self):
    with mock.patch(open_name, create=True) as mock_open:
      mock_open.return_value = mock_file(BASIC)
      self.assertEqual(0, checkteamtags.main())

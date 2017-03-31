# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from collections import OrderedDict
import json
import os
import sys
import unittest

from StringIO import StringIO

import extract_components

SRC = os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)
sys.path.append(os.path.join(SRC, 'third_party', 'pymock'))

import mock

def mock_file_tree(tree):
  os_walk_mocks = []
  file_mocks = {}
  for path in tree:
    if tree[path] is not None:
      os_walk_mocks.append((path, ('ignored'), ('OWNERS', 'dummy.cc')))
      file_mocks[os.path.join(path, 'OWNERS')] = tree[path]
    else:
      os_walk_mocks.append((path, ('ignored'), ('dummy.cc')))

  def custom_mock_open(files_data):
    def inner_open(path, mode='r'):
      ret_val = mock.MagicMock()
      if path in files_data and mode == 'r':

        class mock_opened_file(object):
          def __enter__(self, *args, **kwargs):
            return self

          def __iter__(self, *args, **kwargs):
            return iter(files_data[path].splitlines())

          def __exit__(self, *args, **kwargs):
            pass

        ret_val = mock_opened_file()
      return ret_val
    return inner_open

  def wrapper(func):
    @mock.patch('owners_file_tags.open', custom_mock_open(file_mocks),
                create=True)
    @mock.patch('os.walk', mock.MagicMock(return_value=os_walk_mocks))
    def inner(*args, **kwargs):
      return func(*args, **kwargs)
    return inner
  return wrapper



class ExtractComponentsTest(unittest.TestCase):

  @mock_file_tree({
      'src': 'boss@chromium.org\n',
      'src/dummydir1': 'dummy@chromium.org\n'
                       '# TEAM: dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir2': 'dummy2@chromium.org\n'
                       '# TEAM: other-dummy-team@chromium.org\n'
                       '# COMPONENT: Components>Component2',
      'src/dummydir1/innerdir1': 'dummy@chromium.org\n'
                                 '# TEAM: dummy-specialist-team@chromium.org\n'
                                 '# COMPONENT: Dummy>Component>Subcomponent'})
  def testBaseCase(self):
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      error_code = extract_components.main(['%prog'])
    self.assertEqual(0, error_code)
    result_minus_readme = json.loads(saved_output.getvalue())
    del result_minus_readme['AAA-README']
    self.assertEqual(result_minus_readme, {
        'component-to-team': {
            'Components>Component2': 'other-dummy-team@chromium.org',
            'Dummy>Component': 'dummy-team@chromium.org',
            'Dummy>Component>Subcomponent': 'dummy-specialist-team@chromium.org'
        },
        'dir-to-component': {
            'tools/checkteamtags/src/dummydir1': 'Dummy>Component',
            'tools/checkteamtags/src/dummydir1/innerdir1':
                'Dummy>Component>Subcomponent',
            'tools/checkteamtags/src/dummydir2': 'Components>Component2'
        }})

  @mock_file_tree({
      'src': 'boss@chromium.org\n',
      'src/dummydir1': 'dummy@chromium.org\n'
                       '# TEAM: dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir2': 'dummy2@chromium.org\n'
                       '# TEAM: other-dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir1/innerdir1': 'dummy@chromium.org\n'
                                 '# TEAM: dummy-specialist-team@chromium.org\n'
                                 '# COMPONENT: Dummy>Component>Subcomponent'})
  def testMultipleTeamsOneComponent(self):
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      error_code = extract_components.main(['%prog', '-w'])
    self.assertNotEqual(0, error_code)
    output = saved_output.getvalue()
    self.assertIn('has more than one team assigned to it', output)
    self.assertIn('Not writing to file', output)

  @mock_file_tree({
      'src': 'boss@chromium.org\n',
      'src/dummydir1': 'dummy@chromium.org\n'
                       '# TEAM: dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir2': 'dummy2@chromium.org\n'
                       '# TEAM: other-dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir1/innerdir1': 'dummy@chromium.org\n'
                                 '# TEAM: dummy-specialist-team@chromium.org\n'
                                 '# COMPONENT: Dummy>Component>Subcomponent'})
  def testVerbose(self):
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      extract_components.main(['%prog', '-v'])
    output = saved_output.getvalue()
    self.assertIn('src/OWNERS has no COMPONENT tag', output)

  @mock_file_tree({
      'src': 'boss@chromium.org\n',
      'src/dummydir1': 'dummy@chromium.org\n'
                       '# TEAM: dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir2': 'dummy2@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir1/innerdir1': 'dummy@chromium.org\n'
                                 '# TEAM: dummy-specialist-team@chromium.org\n'
                                 '# COMPONENT: Dummy>Component>Subcomponent'})
  def testCoverage(self):
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      extract_components.main(['%prog', '-s 2'])
    output = saved_output.getvalue()
    self.assertIn('4 OWNERS files in total.', output)
    self.assertIn('3 (75.00%) OWNERS files have COMPONENT', output)
    self.assertIn('2 (50.00%) OWNERS files have TEAM and COMPONENT', output)

  @mock_file_tree({
      'src': 'boss@chromium.org\n',
      'src/dummydir1': 'dummy@chromium.org\n'
                       '# TEAM: dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir2': 'dummy2@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir1/innerdir1': 'dummy@chromium.org\n'
                                 '# TEAM: dummy-specialist-team@chromium.org\n'
                                 '# COMPONENT: Dummy>Component>Subcomponent'})
  def testCompleteCoverage(self):
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      extract_components.main(['%prog', '-c'])
    output = saved_output.getvalue()
    self.assertIn('4 OWNERS files in total.', output)
    self.assertIn('3 (75.00%) OWNERS files have COMPONENT', output)
    self.assertIn('2 (50.00%) OWNERS files have TEAM and COMPONENT', output)
    self.assertIn('4 OWNERS files at depth 0', output)

  # We use OrderedDict here to guarantee that mocked version of os.walk returns
  # directories in the specified order (top-down).
  @mock_file_tree(OrderedDict([
      ('chromium/src', 'boss@chromium.org\n'),
      ('chromium/src/dir1', 'dummy@chromium.org\n'
                            '# TEAM: dummy-team@chromium.org\n'
                            '# COMPONENT: Dummy>Component'),
      ('chromium/src/dir2', 'dummy2@chromium.org\n'
                            '# TEAM: other-dummy-team@chromium.org\n'
                            '# COMPONENT: Dummy>Component2'),
      ('chromium/src/dir1/subdir', 'dummy@chromium.org'),
      ('chromium/src/dir2/subdir', None),
      ('third_party/WebKit/LayoutTests/foo',
           '# TEAM: dummy-team-3@chromium.org\n'),
      ('third_party/WebKit/LayoutTests/bar',
           '# TEAM: dummy-team-3@chromium.org\n'
           '# COMPONENT: Dummy>Component3\n'),
  ]))
  def testIncludesSubdirectoriesWithNoOwnersFileOrNoComponentTag(self):
    self.maxDiff = None  # This helps to see assertDictEqual errors in full.
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      error_code = extract_components.main(['%prog', '--include-subdirs', ''])
    self.assertEqual(0, error_code)
    result_minus_readme = json.loads(saved_output.getvalue())
    del result_minus_readme['AAA-README']
    self.assertDictEqual(result_minus_readme, {
        u'component-to-team': {
            u'Dummy>Component': u'dummy-team@chromium.org',
            u'Dummy>Component2': u'other-dummy-team@chromium.org',
            u'Dummy>Component3': u'dummy-team-3@chromium.org',
        },
        u'dir-to-component': {
            u'chromium/src/dir1': u'Dummy>Component',
            u'chromium/src/dir1/subdir': u'Dummy>Component',
            u'chromium/src/dir2': u'Dummy>Component2',
            u'chromium/src/dir2/subdir': u'Dummy>Component2',
            u'third_party/WebKit/LayoutTests/bar': u'Dummy>Component3',
        },
        u'dir-to-team': {
            u'third_party/WebKit/LayoutTests/foo': u'dummy-team-3@chromium.org',
        }})

  @mock_file_tree({
      'src': 'boss@chromium.org\n',
      'src/dummydir1': 'dummy@chromium.org\n'
                       '# TEAM: dummy-team@chromium.org\n'
                       '# COMPONENT: Dummy>Component',
      'src/dummydir1/innerdir1': 'dummy@chromium.org\n'
                                 '# TEAM: dummy-specialist-team@chromium.org\n'
                                 '# COMPONENT: Dummy>Component>Subcomponent'})
  def testDisplayFile(self):
    saved_output = StringIO()
    with mock.patch('sys.stdout', saved_output):
      extract_components.main(['%prog', '-m 2'])
    output = saved_output.getvalue()
    self.assertIn('OWNERS files that have missing team and component by depth:',
                  output)
    self.assertIn('at depth 0', output)
    self.assertIn('[\'tools/checkteamtags/src/OWNERS\']', output)

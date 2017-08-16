# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story

class IndexedDBEndurePage(page_module.Page):

  def __init__(self, subtest, page_set):
    super(IndexedDBEndurePage, self).__init__(
      url='file://indexeddb_perf/perf_test.html',
      page_set=page_set,
      name='indexeddb-endure-' + subtest)
    self._subtest = subtest

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript(
        'window.testFilter = {{ subtest }};', subtest=self._subtest)
    with action_runner.CreateInteraction('Action_Test'):
      action_runner.ExecuteJavaScript('window.test();')
      action_runner.WaitForJavaScriptCondition(
          'window.done', timeout=600)

class IndexedDBEndurePageSet(story.StorySet):
  """The IndexedDB Endurance page set.

  This page set exercises various common operations in IndexedDB.
  """

  def __init__(self):
    super(IndexedDBEndurePageSet, self).__init__()
    tests = [
      'testCreateAndDeleteDatabases',
      'testCreateAndDeleteDatabase',
      'testCreateKeysInStores',
      'testRandomReadsAndWritesWithoutIndex',
      'testRandomReadsAndWritesWithIndex',
      'testReadCacheWithoutIndex',
      'testReadCacheWithIndex',
      'testCreateAndDeleteIndex',
      'testWalkingMultipleCursors',
      'testCursorSeeksWithoutIndex',
      'testCursorSeeksWithIndex'
    ]
    for test in tests:
      self.AddStory(IndexedDBEndurePage(test, self))

# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry.page import legacy_page_test
from telemetry import story


NUM_BLOB_MASS_CREATE_READS = 15


class BlobCreateThenRead(page_module.Page):

  def __init__(self, write_method, blob_sizes, page_set):
    super(BlobCreateThenRead, self).__init__(
      url='file://blob/blob-workshop.html',
      page_set=page_set,
      name='blob-create-read-' + write_method)
    self._blob_sizes = blob_sizes

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('disableUI = true;')

    for size_bytes in self._blob_sizes:
      with action_runner.CreateInteraction('Action_CreateAndReadBlob',
                                           repeatable=True):
        action_runner.ExecuteJavaScript(
            'createAndRead({{ size }});', size=size_bytes)
        action_runner.WaitForJavaScriptCondition(
            'doneReading === true || errors', timeout=60)

    errors = action_runner.EvaluateJavaScript('errors')
    if errors:
      raise legacy_page_test.Failure('Errors on page: ' + ', '.join(errors))


class BlobMassCreate(page_module.Page):
  def __init__(self, write_method, blob_sizes, page_set):
    super(BlobMassCreate, self).__init__(
      url='file://blob/blob-workshop.html',
      page_set=page_set,
      name='blob-mass-create-' + write_method)
    self._blob_sizes = blob_sizes

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('disableUI = true;')

    # Add blobs
    for size_bytes in self._blob_sizes:
      with action_runner.CreateInteraction('Action_CreateBlob',
                                           repeatable=True):
        action_runner.ExecuteJavaScript(
            'createBlob({{ size }});', size=size_bytes)

    # Read blobs
    for _ in range(0, NUM_BLOB_MASS_CREATE_READS):
      with action_runner.CreateInteraction('Action_ReadBlobs',
                                           repeatable=True):
        action_runner.ExecuteJavaScript('readBlobsSerially();')
        action_runner.WaitForJavaScriptCondition(
            'doneReading === true || errors', timeout=60)
    # Clean up blobs. Make sure this flag is turned on:
    # --enable-experimental-web-platform-features
    action_runner.ExecuteJavaScript('garbageCollect();')

    errors = action_runner.EvaluateJavaScript('errors')
    if errors:
      raise legacy_page_test.Failure('Errors on page: ' + ', '.join(errors))


class BlobWorkshopPageSet(story.StorySet):
  """The BlobWorkshop page set."""

  def __init__(self):
    super(BlobWorkshopPageSet, self).__init__()
    self.AddStory(
        BlobMassCreate('2Bx200', [2] * 200, self))
    self.AddStory(
        BlobMassCreate('1KBx200', [1024] * 200, self))
    self.AddStory(
        BlobMassCreate('150KBx200', [150 * 1024] * 200, self))
    self.AddStory(
        BlobMassCreate('1MBx200', [1024 * 1024] * 200, self))
    self.AddStory(
        BlobMassCreate('10MBx30', [10 * 1024 * 1024] * 30, self))
    # http://crbug.com/510815
    #self.AddStory(
    #    BlobMassCreate('80MBx5', [80 * 1024 * 1024] * 5, self))

    self.AddStory(BlobCreateThenRead('2Bx200', [2] * 200, self))
    self.AddStory(BlobCreateThenRead('1KBx200', [1024] * 200, self))
    self.AddStory(
        BlobCreateThenRead('150KBx200', [150 * 1024 - 1] * 200, self))
    self.AddStory(BlobCreateThenRead('1MBx200', [1024 * 1024] * 200, self))
    self.AddStory(
        BlobCreateThenRead('10MBx30', [10 * 1024 * 1024] * 30, self))
    self.AddStory(
        BlobCreateThenRead('80MBx5', [80 * 1024 * 1024] * 5, self))

# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class ImageDecodingMeasurementPage(page_module.Page):

  def __init__(self, url, page_set):
    super(ImageDecodingMeasurementPage, self).__init__(url=url,
                                                       page_set=page_set)
    self.image_decoding_measurement_limit_results_to_min_iterations = True

  def RunNavigateSteps(self, action_runner):
    super(ImageDecodingMeasurementPage, self).RunNavigateSteps(action_runner)
    action_runner.ExecuteJavaScript('runBenchmark();')
    action_runner.WaitForJavaScriptCondition('isDone')


class ImageDecodingMeasurementPageSet(story.StorySet):

  """ A directed benchmark of image decoding performance """

  def __init__(self):
    super(ImageDecodingMeasurementPageSet, self).__init__()
    self.image_decoding_measurement_limit_results_to_min_iterations = True

    urls_list = [
      'file://../../../chrome/test/data/image_decoding/image_decoding.html?gif',
      'file://../../../chrome/test/data/image_decoding/image_decoding.html?jpg',
      'file://../../../chrome/test/data/image_decoding/image_decoding.html?png',
      'file://../../../chrome/test/data/image_decoding/image_decoding.html?webp'
    ]

    for url in urls_list:
      self.AddStory(ImageDecodingMeasurementPage(url, self))

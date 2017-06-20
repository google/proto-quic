# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page
from telemetry import story


archive_data_file_path = 'data/service_worker.json'


class ServiceWorkerPageSet(story.StorySet):
  """Page set of applications using ServiceWorker"""

  def __init__(self):
    super(ServiceWorkerPageSet, self).__init__(
        archive_data_file=archive_data_file_path,
        cloud_storage_bucket=story.PARTNER_BUCKET)

    # Why: the first application using ServiceWorker
    # 1st time: registration
    self.AddStory(page.Page(
        'https://jakearchibald.github.io/trained-to-thrill/', self,
        name='first_load', make_javascript_deterministic=False))
    # 2nd time: 1st onfetch with caching
    self.AddStory(page.Page(
        'https://jakearchibald.github.io/trained-to-thrill/', self,
        name='second_load', make_javascript_deterministic=False))
    # 3rd time: 2nd onfetch from cache
    self.AddStory(page.Page(
        'https://jakearchibald.github.io/trained-to-thrill/', self,
        name='third_load', make_javascript_deterministic=False))

    # Why: another caching strategy: cache.addAll in oninstall handler
    # 1st time: registration and caching
    self.AddStory(page.Page(
        'https://jakearchibald.github.io/svgomg/', self,
        name='svgomg_first_load', make_javascript_deterministic=False))
    # 2nd time: onfetch from cache
    self.AddStory(page.Page(
        'https://jakearchibald.github.io/svgomg/', self,
        name='svgomg_second_load', make_javascript_deterministic=False))


class ServiceWorkerStoryExpectations(story.expectations.StoryExpectations):
  def SetExpectations(self):
    pass # Nothing disabled.

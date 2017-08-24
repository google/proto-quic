# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story

from page_sets import webgl_supported_shared_state


class MapsPage(page_module.Page):
  """Google Maps benchmarks and pixel tests.

  The Maps team gave us a build of their test. The only modification
  to the test was to config.js, where the width and height query args
  were set to 800 by 600. The WPR was recorded with:

  tools/perf/record_wpr smoothness_maps --browser=system

  This produced maps_???.wpr, maps_???.wpr.sha1 and maps.json.

  It's worth noting that telemetry no longer allows replaying a URL that
  refers to localhost. If the recording was created for the locahost URL, one
  can update the host name by running:

    web-page-replay/httparchive.py remap-host maps_004.wpr \
    localhost:8000 map-test

  (web-page-replay/ can be found in third_party/catapult/telemetry/third_party/)

  After updating the host name in the WPR archive, or recording a
  newly-numbered WPR archive, please remember to update
  content/test/gpu/gpu_tests/maps_integration_test.py (and potentially
  its pixel expectations) as well.

  To upload the maps_???.wpr to cloud storage, one would run:

    depot_tools/upload_to_google_storage.py --bucket=chromium-telemetry \
    maps_???.wpr
  """

  def __init__(self, page_set):
    url = 'http://map-test/performance.html'
    super(MapsPage, self).__init__(
      url=url,
      page_set=page_set,
      shared_page_state_class=(
          webgl_supported_shared_state.WebGLSupportedSharedState),
      name=url)

  @property
  def skipped_gpus(self):
    # Skip this intensive test on low-end devices. crbug.com/464731
    return ['arm']

  def RunNavigateSteps(self, action_runner):
    super(MapsPage, self).RunNavigateSteps(action_runner)
    action_runner.Wait(3)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('MapAnimation'):
      action_runner.WaitForJavaScriptCondition(
        'window.testMetrics != undefined', timeout=120)


class MapsPageSet(story.StorySet):

  """ Google Maps examples """

  def __init__(self):
    super(MapsPageSet, self).__init__(
        archive_data_file='data/maps.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(MapsPage(self))

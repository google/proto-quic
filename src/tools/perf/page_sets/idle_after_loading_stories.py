# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story

# Chrome has high idle CPU usage on these sites, even after they have quiesced.
SITES = [
  # https://bugs.chromium.org/p/chromium/issues/detail?id=638365
  'http://www.labradortraininghq.com/labrador-training/how-to-crate-train'
  '-a-puppy/#How_Long_DoesIt_Take_To_Crate_Train_A_Puppy',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505990
  # TODO(charliea): Temporarily disable this site, since it causes tracing to
  # explode from too much data. https://crbug.com/647398
  # 'http://abcnews.go.com/',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505601
  'http://www.slideshare.net/patrickmeenan',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505577
  'http://tumblr.all-that-is-interesting.com/',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505553
  'https://instagram.com/cnn/',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505544
  'http://www.sina.com.cn',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505056
  'http://bbc.com/news/uk/',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505054
  'http://www.uol.com.br',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505052
  'http://www.indiatimes.com',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505044
  'http://www.w3schools.com/html/default.asp',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=505002
  'http://www.microsoft.com',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=489936
  'http://capitalone.com',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=481225
  'https://twitter.com/katyperry',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=476158
  'http://bgr.com',

  # https://bugs.chromium.org/p/chromium/issues/detail?id=425474
  'http://www.androidpolice.com/2014/10/20/animation-bonanza-android'
  '-5-0-lollipop-in-gifs/',
]

# TODO(rnephew): Move to seperate file and merge with mac_gpu_sites BasePage.
class _BasePage(page_module.Page):
  def __init__(self, page_set, url, wait_in_seconds):
    super(_BasePage, self).__init__(url=url, page_set=page_set)
    self._wait_in_seconds = wait_in_seconds

  def RunPageInteractions(self, action_runner):
    action_runner.Wait(self._wait_in_seconds)


class IdleAfterLoadingStories(story.StorySet):
  """Historically, Chrome has high CPU usage on these sites after the page has
  loaded. These user stories let Chrome idle on the page."""

  def __init__(self, wait_in_seconds=0):
    super(IdleAfterLoadingStories, self).__init__(
        archive_data_file='data/idle_after_loading_stories.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    # Chrome has high idle CPU usage on this site, even after its quiesced.
    # https://crbug.com/638365.
    for url in SITES:
      self.AddStory(_BasePage(self, url, wait_in_seconds))

# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class BasicPlayPage(page_module.Page):

  def __init__(self, url, page_set, name=''):
    super(BasicPlayPage, self).__init__(url=url, page_set=page_set, name=name)
    self.add_browser_metrics = True

  def PlayAction(self, action_runner):
    action_runner.PlayMedia(playing_event_timeout_in_seconds=60,
                            ended_event_timeout_in_seconds=60)

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

  def SeekBeforeAndAfterPlayhead(self, action_runner):
    action_runner.PlayMedia(playing_event_timeout_in_seconds=60)
    # Wait for 1 second so that we know the play-head is at ~1s.
    action_runner.Wait(1)
    # Seek to before the play-head location.
    action_runner.SeekMedia(seconds=0.5, timeout_in_seconds=60,
                            label='seek_warm')
    # Seek to after the play-head location.
    action_runner.SeekMedia(seconds=15, timeout_in_seconds=60,
                            label='seek_cold')

class SeekBeforeAndAfterPlayheadPage(BasicPlayPage):

  def __init__(self, url, page_set, name):
    super(SeekBeforeAndAfterPlayheadPage, self).__init__(url=url,
                                                         page_set=page_set,
                                                         name=name)
    self.add_browser_metrics = False

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class MediaCnsCasesPageSet(story.StorySet):

  """ Media benchmark on network constrained conditions. """

  def __init__(self):
    super(MediaCnsCasesPageSet, self).__init__()

    urls_list = [
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_webm&src=tulip2.webm&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_webm&src=tulip2.webm&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_webm&src=tulip2.webm&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_ogv&src=tulip2.ogv&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_ogv&src=tulip2.ogv&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_ogv&src=tulip2.ogv&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_mp4&src=tulip2.mp4&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_mp4&src=tulip2.mp4&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_mp4&src=tulip2.mp4&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_wav&src=tulip2.wav&type=audio&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_wav&src=tulip2.wav&type=audio&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_wav&src=tulip2.wav&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_ogg&src=tulip2.ogg&type=audio&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_ogg&src=tulip2.ogg&type=audio&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_ogg&src=tulip2.ogg&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_mp3&src=tulip2.mp3&type=audio&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_mp3&src=tulip2.mp3&type=audio&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_mp3&src=tulip2.mp3&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=no_constraints_m4a&src=tulip2.m4a&type=audio&net=none',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=cable_m4a&src=tulip2.m4a&type=audio&net=cable',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_m4a&src=tulip2.m4a&type=audio&net=wifi'
    ]

    for url in urls_list:
      self.AddStory(BasicPlayPage(url, self))

    urls_list2 = [
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_mp3&src=tulip2.mp3&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_m4a&src=tulip2.m4a&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_ogg&src=tulip2.ogg&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_wav&src=tulip2.wav&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_mp4&src=tulip2.mp4&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_ogv&src=tulip2.ogv&type=audio&net=wifi',
      # pylint: disable=line-too-long
      'file://tough_video_cases/video.html?id=wifi_webm&src=tulip2.webm&type=audio&net=wifi'
    ]

    for url in urls_list2:
      if url in urls_list:
        name = 'seek_' + url
      else:
        name = ''
      self.AddStory(SeekBeforeAndAfterPlayheadPage(url, self, name=name))

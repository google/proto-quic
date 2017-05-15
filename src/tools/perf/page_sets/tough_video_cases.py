# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story

_PAGE_TAGS_LIST = [
    # Audio codecs:
    'pcm',
    'mp3',
    'aac',
    'vorbis',
    'opus',
    # Video codecs:
    'h264',
    'vp8',
    'vp9',
    # Test types:
    'audio_video',
    'audio_only',
    'video_only',
    # Other filter tags:
    'is_50fps',
    'is_4k',
    # Play action
    'seek',
    'normal_play',
]


class ToughVideoCasesPage(page_module.Page):

  def __init__(self, url, page_set, tags):
    if tags:
      for t in tags:
        assert t in _PAGE_TAGS_LIST
    super(ToughVideoCasesPage, self).__init__(
        url=url, page_set=page_set, tags=tags)

  def PlayAction(self, action_runner):
    # Play the media until it has finished or it times out.
    action_runner.PlayMedia(playing_event_timeout_in_seconds=60,
                            ended_event_timeout_in_seconds=60)

  def SeekBeforeAndAfterPlayhead(self, action_runner,
                                 action_timeout_in_seconds=60):
    timeout = action_timeout_in_seconds
    # Start the media playback.
    action_runner.PlayMedia(
        playing_event_timeout_in_seconds=timeout)
    # Wait for 1 second so that we know the play-head is at ~1s.
    action_runner.Wait(1)
    # Seek to before the play-head location.
    action_runner.SeekMedia(seconds=0.5, timeout_in_seconds=timeout,
                            label='seek_warm')
    # Seek to after the play-head location.
    action_runner.SeekMedia(seconds=9, timeout_in_seconds=timeout,
                            label='seek_cold')


class Page2(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page2, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd.ogg&type=audio',
      page_set=page_set,
      tags=['vorbis', 'audio_only'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page4(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page4, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080.webm',
      page_set=page_set,
      tags=['is_50fps', 'vp8', 'vorbis', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page7(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page7, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.ogg&type=audio',
      page_set=page_set,
      tags=['vorbis', 'audio_only', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page8(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page8, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.wav&type=audio',
      page_set=page_set,
      tags=['pcm', 'audio_only', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page11(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page11, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080.mp4',
      page_set=page_set,
      tags=['is_50fps', 'h264', 'aac', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page12(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page12, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd2160.mp4',
      page_set=page_set,
      tags=['is_4k', 'is_50fps', 'h264', 'aac', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page13(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page13, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp3&type=audio',
      page_set=page_set,
      tags=['mp3', 'audio_only', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page14(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page14, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp4',
      page_set=page_set,
      tags=['h264', 'aac', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page15(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page15, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.m4a&type=audio',
      page_set=page_set,
      tags=['aac', 'audio_only', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page16(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page16, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.webm',
      page_set=page_set,
      tags=['is_4k', 'vp8', 'vorbis', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page17(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page17, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.mp4',
      page_set=page_set,
      tags=['is_4k', 'h264', 'aac', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page19(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page19, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.ogg&type=audio&seek',
      page_set=page_set,
      tags=['vorbis', 'audio_only', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page20(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page20, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.wav&type=audio&seek',
      page_set=page_set,
      tags=['pcm', 'audio_only', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page23(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page23, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp3&type=audio&seek',
      page_set=page_set,
      tags=['mp3', 'audio_only', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page24(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page24, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp4&seek',
      page_set=page_set,
      tags=['h264', 'aac', 'audio_video', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page25(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page25, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.webm&seek',
      page_set=page_set,
      tags=['is_4k', 'vp8', 'vorbis', 'audio_video', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page26(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page26, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.mp4&seek',
      page_set=page_set,
      tags=['is_4k', 'h264', 'aac', 'audio_video', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page30(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page30, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.vp9.webm',
      page_set=page_set,
      tags=['vp9', 'opus', 'audio_video', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page31(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page31, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.vp9.webm&seek',
      page_set=page_set,
      tags=['vp9', 'opus', 'audio_video', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page32(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page32, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080_vp9.webm',
      page_set=page_set,
      tags=['vp9', 'video_only', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page33(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page33, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080_vp9.webm&seek',
      page_set=page_set,
      tags=['vp9', 'video_only', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page34(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page34, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd720_vp9.webm',
      page_set=page_set,
      tags=['vp9', 'video_only', 'normal_play'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page35(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page35, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd720_vp9.webm&seek',
      page_set=page_set,
      tags=['vp9', 'video_only', 'seek'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page36(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page36, self).__init__(
      url=('file://tough_video_cases/video.html?src='
           'smpte_3840x2160_60fps_vp9.webm&seek'),
      page_set=page_set,
      tags=['is_4k', 'vp9', 'video_only', 'seek'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner,
                                    action_timeout_in_seconds=120)


class ToughVideoCasesPageSet(story.StorySet):
  """
  Description: Video Stack Perf pages that report time_to_play, seek time and
  many other media-specific and generic metrics.
  """
  def __init__(self):
    super(ToughVideoCasesPageSet, self).__init__(
            cloud_storage_bucket=story.PARTNER_BUCKET)

    # Normal play tests:
    self.AddStory(Page2(self))
    self.AddStory(Page4(self))
    self.AddStory(Page7(self))
    self.AddStory(Page8(self))
    self.AddStory(Page11(self))
    self.AddStory(Page12(self))
    self.AddStory(Page13(self))
    self.AddStory(Page14(self))
    self.AddStory(Page15(self))
    self.AddStory(Page16(self))
    self.AddStory(Page17(self))
    self.AddStory(Page30(self))
    self.AddStory(Page32(self))
    self.AddStory(Page34(self))

    # Seek tests:
    self.AddStory(Page19(self))
    self.AddStory(Page20(self))
    self.AddStory(Page23(self))
    self.AddStory(Page24(self))
    self.AddStory(Page25(self))
    self.AddStory(Page26(self))
    self.AddStory(Page31(self))
    self.AddStory(Page33(self))
    self.AddStory(Page35(self))
    self.AddStory(Page36(self))

# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class ToughVideoCasesPage(page_module.Page):

  def __init__(self, url, page_set, tags=None):
    super(ToughVideoCasesPage, self).__init__(
        url=url, page_set=page_set, tags=tags)

  def LoopMixedAudio(self, action_runner):
    action_runner.PlayMedia(selector='#background_audio',
                            playing_event_timeout_in_seconds=60)
    action_runner.LoopMedia(loop_count=50, selector='#mixed_audio')

  def LoopSingleAudio(self, action_runner):
    action_runner.LoopMedia(loop_count=50, selector='#single_audio')

  def PlayAction(self, action_runner):
    action_runner.PlayMedia(playing_event_timeout_in_seconds=60,
                            ended_event_timeout_in_seconds=60)

  def SeekBeforeAndAfterPlayhead(self, action_runner,
                                 action_timeout_in_seconds=60):
    timeout = action_timeout_in_seconds
    # Because an ended timeout is passed, this won't return until the media has
    # played through.
    action_runner.PlayMedia(playing_event_timeout_in_seconds=timeout,
                            ended_event_timeout_in_seconds=timeout)
    # Wait 1 second for no reason in particular.
    action_runner.Wait(1)
    # Seek to before the play-head location.
    action_runner.SeekMedia(seconds=0.5, timeout_in_seconds=timeout,
                            label='seek_warm')
    # Seek to after the play-head location.
    action_runner.SeekMedia(seconds=9, timeout_in_seconds=timeout,
                            label='seek_cold')


class Page1(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page1, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd.wav&type=audio',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page2(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page2, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd.ogg&type=audio',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page3(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page3, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080.ogv',
      page_set=page_set)

    self.add_browser_metrics = True
    self.is_50fps = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page4(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page4, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080.webm',
      page_set=page_set, tags=['is_50fps'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page5(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page5, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd2160.ogv',
      page_set=page_set, tags=['is_4k', 'is_50fps'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page6(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page6, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd2160.webm',
      page_set=page_set, tags=['is_4k', 'is_50fps'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page7(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page7, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.ogg&type=audio',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page8(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page8, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.wav&type=audio',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page9(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page9, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.ogv',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page10(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page10, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.webm',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page11(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page11, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080.mp4',
      page_set=page_set, tags=['is_50fps'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page12(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page12, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd2160.mp4',
      page_set=page_set, tags=['is_4k', 'is_50fps'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page13(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page13, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp3&type=audio',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page14(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page14, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp4',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page15(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page15, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.m4a&type=audio',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page16(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page16, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.webm',
      page_set=page_set, tags=['is_4k'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page17(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page17, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.mp4',
      page_set=page_set, tags=['is_4k'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page18(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page18, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.ogv',
      page_set=page_set, tags=['is_4k'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)


class Page19(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page19, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.ogg&type=audio',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page20(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page20, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.wav&type=audio',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page21(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page21, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.ogv',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page22(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page22, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.webm',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page23(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page23, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp3&type=audio',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page24(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page24, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp4',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page25(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page25, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.webm',
      page_set=page_set, tags=['is_4k'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page26(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page26, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.mp4',
      page_set=page_set, tags=['is_4k'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page27(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page27, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.ogv',
      page_set=page_set, tags=['is_4k'])

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)


class Page28(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page28, self).__init__(
      url='file://tough_video_cases/audio_playback.html?id=single_audio',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.LoopSingleAudio(action_runner)


class Page29(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page29, self).__init__(
      url='file://tough_video_cases/audio_playback.html?id=mixed_audio',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.LoopMixedAudio(action_runner)

class Page30(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page30, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.vp9.webm',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

class Page31(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page31, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.vp9.webm',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)

class Page32(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page32, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080_vp9.webm',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

class Page33(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page33, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080_vp9.webm',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)

class Page34(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page34, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd720_vp9.webm',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

class Page35(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page35, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd720_vp9.webm',
      page_set=page_set)

    self.skip_basic_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)

class Page36(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page36, self).__init__(
      url=('file://tough_video_cases/video.html?src='
           'smpte_3840x2160_60fps_vp9.webm'),
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner,
                                    action_timeout_in_seconds=120)

class Page37(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page37, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080_vp9.webm&canvas=true',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

class Page38(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page38, self).__init__(
      url='file://tough_video_cases/video.html?src=tulip2.mp4&canvas=true',
      page_set=page_set)

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.SeekBeforeAndAfterPlayhead(action_runner)

class Page39(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page39, self).__init__(
      url='file://tough_video_cases/video.html?src=garden2_10s.webm&canvas=true',
      page_set=page_set, tags=['is_4k'])

    self.add_browser_metrics = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

class Page40(ToughVideoCasesPage):

  def __init__(self, page_set):
    super(Page40, self).__init__(
      url='file://tough_video_cases/video.html?src=crowd1080.ogv&canvas=true',
      page_set=page_set)

    self.add_browser_metrics = True
    self.is_50fps = True

  def RunPageInteractions(self, action_runner):
    self.PlayAction(action_runner)

class ToughVideoCasesPageSet(story.StorySet):
  """
  Description: Video Stack Perf benchmark that report time_to_play.
  """
  def __init__(self):
    super(ToughVideoCasesPageSet, self).__init__(
            cloud_storage_bucket=story.PARTNER_BUCKET)

    self.AddStory(Page1(self))
    self.AddStory(Page2(self))
    self.AddStory(Page3(self))
    self.AddStory(Page4(self))
    self.AddStory(Page5(self))
    self.AddStory(Page6(self))
    self.AddStory(Page7(self))
    self.AddStory(Page8(self))
    self.AddStory(Page9(self))
    self.AddStory(Page10(self))
    self.AddStory(Page11(self))
    self.AddStory(Page12(self))
    self.AddStory(Page13(self))
    self.AddStory(Page14(self))
    self.AddStory(Page15(self))
    self.AddStory(Page16(self))
    self.AddStory(Page17(self))
    self.AddStory(Page18(self))
    self.AddStory(Page30(self))
    self.AddStory(Page32(self))
    self.AddStory(Page34(self))
    self.AddStory(Page36(self))
    self.AddStory(Page37(self))
    self.AddStory(Page38(self))
    self.AddStory(Page39(self))
    self.AddStory(Page40(self))


class ToughVideoCasesExtraPageSet(story.StorySet):
  """
  Description: Video Stack Perf benchmark that don't report time_to_play.
  """
  def __init__(self):
    super(ToughVideoCasesExtraPageSet, self).__init__(
            cloud_storage_bucket=story.PARTNER_BUCKET)

    self.AddStory(Page19(self))
    self.AddStory(Page20(self))
    self.AddStory(Page21(self))
    self.AddStory(Page22(self))
    self.AddStory(Page23(self))
    self.AddStory(Page24(self))
    self.AddStory(Page25(self))
    self.AddStory(Page26(self))
    self.AddStory(Page27(self))
    self.AddStory(Page28(self))
    self.AddStory(Page29(self))
    self.AddStory(Page31(self))
    self.AddStory(Page33(self))
    self.AddStory(Page35(self))

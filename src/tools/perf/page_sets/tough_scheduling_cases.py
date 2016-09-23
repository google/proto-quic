# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


class ToughSchedulingCasesPage(page_module.Page):

  def __init__(self, url, page_set):
    super(ToughSchedulingCasesPage, self).__init__(
        url=url, page_set=page_set, credentials_path='data/credentials.json',
        shared_page_state_class=shared_page_state.SharedMobilePageState)
    self.archive_data_file = 'data/tough_scheduling_cases.json'

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class Page1(ToughSchedulingCasesPage):

  """Why: Simulate oversubscribed main thread."""

  def __init__(self, page_set):
    super(Page1, self).__init__(
        url='file://tough_scheduling_cases/simple_text_page.html?main_busy',
        page_set=page_set)

    self.synthetic_delays = {'cc.BeginMainFrame': {'target_duration': 0.008}}


class Page2(ToughSchedulingCasesPage):

  """Why: Simulate oversubscribed main thread."""

  def __init__(self, page_set):
    super(Page2, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/simple_text_page.html?main_very_busy',
        page_set=page_set)

    self.synthetic_delays = {'cc.BeginMainFrame': {'target_duration': 0.024}}


class Page3(ToughSchedulingCasesPage):

  """Why: Simulate a page with a a few graphics layers."""

  def __init__(self, page_set):
    super(Page3, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/simple_text_page.html?medium_layers',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.DrawAndSwap': {'target_duration': 0.004},
        'gpu.PresentingFrame': {'target_duration': 0.004},
        'cc.BeginMainFrame': {'target_duration': 0.004}
    }


class Page4(ToughSchedulingCasesPage):

  """Why: Simulate a page with many graphics layers."""

  def __init__(self, page_set):
    super(Page4, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/simple_text_page.html?many_layers',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.DrawAndSwap': {'target_duration': 0.012},
        'gpu.PresentingFrame': {'target_duration': 0.012},
        'cc.BeginMainFrame': {'target_duration': 0.012}
    }


class Page5(ToughSchedulingCasesPage):

  """Why: Simulate a page with expensive recording and rasterization."""

  def __init__(self, page_set):
    super(Page5, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/simple_text_page.html?medium_raster',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.RasterRequiredForActivation': {'target_duration': 0.004},
        'cc.BeginMainFrame': {'target_duration': 0.004},
        'gpu.AsyncTexImage': {'target_duration': 0.004}
    }


class Page6(ToughSchedulingCasesPage):

  """Why: Simulate a page with expensive recording and rasterization."""

  def __init__(self, page_set):
    super(Page6, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/simple_text_page.html?heavy_raster',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.RasterRequiredForActivation': {'target_duration': 0.024},
        'cc.BeginMainFrame': {'target_duration': 0.024},
        'gpu.AsyncTexImage': {'target_duration': 0.024}
    }


class Page7(ToughSchedulingCasesPage):

  """Why: Medium cost touch handler."""

  def __init__(self, page_set):
    super(Page7, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/touch_handler_scrolling.html?medium_handler',
        page_set=page_set)

    self.synthetic_delays = {'blink.HandleInputEvent':
                             {'target_duration': 0.008}}


class Page8(ToughSchedulingCasesPage):

  """Why: Slow touch handler."""

  def __init__(self, page_set):
    super(Page8, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/touch_handler_scrolling.html?slow_handler',
        page_set=page_set)

    self.synthetic_delays = {'blink.HandleInputEvent':
                             {'target_duration': 0.024}}


class Page9(ToughSchedulingCasesPage):

  """Why: Touch handler that often takes a long time."""

  def __init__(self, page_set):
    super(Page9, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/touch_handler_scrolling.html?janky_handler',
        page_set=page_set)

    self.synthetic_delays = {'blink.HandleInputEvent':
                             {'target_duration': 0.024, 'mode': 'alternating'}
                            }


class Page10(ToughSchedulingCasesPage):

  """Why: Touch handler that occasionally takes a long time."""

  def __init__(self, page_set):
    super(Page10, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/touch_handler_scrolling.html?occasionally_janky_handler',
        page_set=page_set)

    self.synthetic_delays = {'blink.HandleInputEvent':
                             {'target_duration': 0.024, 'mode': 'oneshot'}}


class Page11(ToughSchedulingCasesPage):

  """Why: Super expensive touch handler causes browser to scroll after a
  timeout."""

  def __init__(self, page_set):
    super(Page11, self).__init__(
        # pylint: disable=line-too-long
        url='file://tough_scheduling_cases/touch_handler_scrolling.html?super_slow_handler',
        page_set=page_set)

    self.synthetic_delays = {'blink.HandleInputEvent':
                             {'target_duration': 0.2}}


class Page12(ToughSchedulingCasesPage):

  """Why: Super expensive touch handler that only occupies a part of the page.
  """

  def __init__(self, page_set):
    super(Page12, self).__init__(
        url='file://tough_scheduling_cases/div_touch_handler.html',
        page_set=page_set)

    self.synthetic_delays = {'blink.HandleInputEvent': {'target_duration': 0.2}}


class Page13(ToughSchedulingCasesPage):

  """Why: Test a moderately heavy requestAnimationFrame handler."""

  def __init__(self, page_set):
    super(Page13, self).__init__(
        url='file://tough_scheduling_cases/raf.html?medium_handler',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.RasterRequiredForActivation': {'target_duration': 0.004},
        'cc.BeginMainFrame': {'target_duration': 0.004},
        'gpu.AsyncTexImage': {'target_duration': 0.004}
    }


class Page14(ToughSchedulingCasesPage):

  """Why: Test a moderately heavy requestAnimationFrame handler."""

  def __init__(self, page_set):
    super(Page14, self).__init__(
        url='file://tough_scheduling_cases/raf.html?heavy_handler',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.RasterRequiredForActivation': {'target_duration': 0.024},
        'cc.BeginMainFrame': {'target_duration': 0.024},
        'gpu.AsyncTexImage': {'target_duration': 0.024}
    }


class Page15(ToughSchedulingCasesPage):

  """Why: Simulate a heavily GPU bound page."""

  def __init__(self, page_set):
    super(Page15, self).__init__(
        url='file://tough_scheduling_cases/raf.html?gpu_bound',
        page_set=page_set)

    self.synthetic_delays = {'gpu.PresentingFrame': {'target_duration': 0.1}}


class Page16(ToughSchedulingCasesPage):

  """Why: Test a requestAnimationFrame handler with a heavy first frame."""

  def __init__(self, page_set):
    super(Page16, self).__init__(
        url='file://tough_scheduling_cases/raf.html?heavy_first_frame',
        page_set=page_set)

    self.synthetic_delays = {'cc.BeginMainFrame': {'target_duration': 0.15,
                                                   'mode': 'oneshot'}}


class Page17(ToughSchedulingCasesPage):

  """Why: Medium stress test for the scheduler."""

  def __init__(self, page_set):
    super(Page17, self).__init__(
        url='file://tough_scheduling_cases/raf_touch_animation.html?medium',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.DrawAndSwap': {'target_duration': 0.004},
        'cc.BeginMainFrame': {'target_duration': 0.004}
    }


class Page18(ToughSchedulingCasesPage):

  """Why: Heavy stress test for the scheduler."""

  def __init__(self, page_set):
    super(Page18, self).__init__(
        url='file://tough_scheduling_cases/raf_touch_animation.html?heavy',
        page_set=page_set)

    self.synthetic_delays = {
        'cc.DrawAndSwap': {'target_duration': 0.012},
        'cc.BeginMainFrame': {'target_duration': 0.012}
    }


class Page19(ToughSchedulingCasesPage):

  """Why: Both main and impl thread animating concurrently."""

  def __init__(self, page_set):
    super(Page19, self).__init__(
        url='file://tough_scheduling_cases/split_animation.html',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('SplitAnimation'):
      action_runner.Wait(3)


class Page20(ToughSchedulingCasesPage):

  """Why: Simple JS touch dragging."""

  def __init__(self, page_set):
    super(Page20, self).__init__(
        url='file://tough_scheduling_cases/simple_touch_drag.html',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollElement(
          selector='#card',
          use_touch=True,
          direction='up',
          speed_in_pixels_per_second=150,
          distance=400)


class EmptyTouchHandlerPage(ToughSchedulingCasesPage):

  """Why: Scrolling on a page with a touch handler that consumes no events but
      may be slow."""

  def __init__(self, name, desktop, slow_handler, bounce, page_set):
    super(EmptyTouchHandlerPage, self).__init__(
        url='file://tough_scheduling_cases/empty_touch_handler' +
        ('_desktop' if desktop else '') + '.html?' + name,
        page_set=page_set)

    if slow_handler:
      self.synthetic_delays = {
          'blink.HandleInputEvent': {'target_duration': 0.2}
      }

    self.bounce = bounce

  def RunPageInteractions(self, action_runner):
    if self.bounce:
      with action_runner.CreateGestureInteraction('ScrollBounceAction'):
        action_runner.ScrollBouncePage()
    else:
      with action_runner.CreateGestureInteraction('ScrollAction'):
        # Speed and distance are tuned to run exactly as long as a scroll
        # bounce.
        action_runner.ScrollPage(use_touch=True, speed_in_pixels_per_second=400,
                                 distance=2100)


class SynchronizedScrollOffsetPage(ToughSchedulingCasesPage):

  """Why: For measuring the latency of scroll-synchronized effects."""

  def __init__(self, page_set):
    super(SynchronizedScrollOffsetPage, self).__init__(
        url='file://tough_scheduling_cases/sync_scroll_offset.html',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollBounceAction'):
      action_runner.ScrollBouncePage()


class SecondBatchJsPage(ToughSchedulingCasesPage):

  """Why: For testing dynamically loading a large batch of Javascript and
          running a part of it in response to user input.
  """

  def __init__(self, page_set, variant='medium'):
    super(SecondBatchJsPage, self).__init__(
        url='file://tough_scheduling_cases/second_batch_js.html?%s' % variant,
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    # Do a dummy tap to warm up the synthetic tap code path.
    action_runner.TapElement(selector='div[id="spinner"]')
    # Begin the action immediately because we want the page to update smoothly
    # even while resources are being loaded.
    action_runner.WaitForJavaScriptCondition('window.__ready !== undefined')

    with action_runner.CreateGestureInteraction('LoadAction'):
      action_runner.ExecuteJavaScript('kickOffLoading()')
      action_runner.WaitForJavaScriptCondition('window.__ready')
      # Click one second after the resources have finished loading.
      action_runner.Wait(1)
      action_runner.TapElement(selector='input[id="run"]')
      # Wait for the test to complete.
      action_runner.WaitForJavaScriptCondition('window.__finished')


class ToughSchedulingCasesPageSet(story.StorySet):

  """Tough scheduler latency test cases."""

  def __init__(self):
    super(ToughSchedulingCasesPageSet, self).__init__(
        archive_data_file='data/tough_scheduling_cases.json',
        cloud_storage_bucket=story.INTERNAL_BUCKET)

    # Why: Simple scrolling baseline
    self.AddStory(ToughSchedulingCasesPage(
        'file://tough_scheduling_cases/simple_text_page.html',
        self))
    self.AddStory(Page1(self))
    self.AddStory(Page2(self))
    self.AddStory(Page3(self))
    self.AddStory(Page4(self))
    # Disabled until crbug.com/413829 is fixed.
    # self.AddStory(Page5(self))
    # Disabled because of crbug.com/413829 and flakiness crbug.com/368532
    # self.AddStory(Page6(self))
    # Why: Touch handler scrolling baseline
    self.AddStory(ToughSchedulingCasesPage(
        'file://tough_scheduling_cases/touch_handler_scrolling.html',
        self))
    self.AddStory(Page7(self))
    self.AddStory(Page8(self))
    self.AddStory(Page9(self))
    self.AddStory(Page10(self))
    self.AddStory(Page11(self))
    self.AddStory(Page12(self))
    # Why: requestAnimationFrame scrolling baseline
    self.AddStory(ToughSchedulingCasesPage(
        'file://tough_scheduling_cases/raf.html',
        self))
    # Why: Test canvas blocking behavior
    self.AddStory(ToughSchedulingCasesPage(
        'file://tough_scheduling_cases/raf_canvas.html',
        self))
    # Disabled until crbug.com/413829 is fixed.
    # self.AddStory(Page13(self))
    # Disabled because of crbug.com/413829 and flakiness crbug.com/368532
    # self.AddStory(Page14(self))
    self.AddStory(Page15(self))
    self.AddStory(Page16(self))
    # Why: Test a requestAnimationFrame handler with concurrent CSS animation
    self.AddStory(ToughSchedulingCasesPage(
        'file://tough_scheduling_cases/raf_animation.html',
        self))
    # Why: Stress test for the scheduler
    self.AddStory(ToughSchedulingCasesPage(
        'file://tough_scheduling_cases/raf_touch_animation.html',
        self))
    self.AddStory(Page17(self))
    self.AddStory(Page18(self))
    self.AddStory(Page19(self))
    self.AddStory(Page20(self))
    # Why: Baseline for scrolling in the presence of a no-op touch handler
    self.AddStory(EmptyTouchHandlerPage(
        name='baseline',
        desktop=False,
        slow_handler=False,
        bounce=False,
        page_set=self))
    # Why: Slow handler blocks scroll start
    self.AddStory(EmptyTouchHandlerPage(
        name='slow_handler',
        desktop=False,
        slow_handler=True,
        bounce=False,
        page_set=self))
    # Why: Slow handler blocks scroll start until touch ACK timeout
    self.AddStory(EmptyTouchHandlerPage(
        name='desktop_slow_handler',
        desktop=True,
        slow_handler=True,
        bounce=False,
        page_set=self))
    # Why: Scroll bounce showing repeated transitions between scrolling and
    # sending synchronous touchmove events.  Should be nearly as fast as
    # scroll baseline.
    self.AddStory(EmptyTouchHandlerPage(
        name='bounce',
        desktop=False,
        slow_handler=False,
        bounce=True,
        page_set=self))
    # Why: Scroll bounce with slow handler, repeated blocking.
    self.AddStory(EmptyTouchHandlerPage(
        name='bounce_slow_handler',
        desktop=False,
        slow_handler=True,
        bounce=True,
        page_set=self))
    # Why: Scroll bounce with slow handler on desktop, blocks only once until
    # ACK timeout.
    self.AddStory(EmptyTouchHandlerPage(
        name='bounce_desktop_slow_handler',
        desktop=True,
        slow_handler=True,
        bounce=True,
        page_set=self))
    # Why: For measuring the latency of scroll-synchronized effects.
    self.AddStory(SynchronizedScrollOffsetPage(page_set=self))
    # Why: Test loading a large amount of Javascript.
    self.AddStory(SecondBatchJsPage(page_set=self, variant='light'))
    self.AddStory(SecondBatchJsPage(page_set=self, variant='medium'))
    self.AddStory(SecondBatchJsPage(page_set=self, variant='heavy'))

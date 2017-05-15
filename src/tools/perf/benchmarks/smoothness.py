# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import multiprocessing

from core import perf_benchmark

from benchmarks import silk_flags
from measurements import smoothness
import page_sets
import page_sets.key_silk_cases
from telemetry import benchmark


class _Smoothness(perf_benchmark.PerfBenchmark):
  """Base class for smoothness-based benchmarks."""

  # Certain smoothness pages do not perform gesture scrolling, in turn yielding
  # an empty first_gesture_scroll_update_latency result. Such empty results
  # should be ignored, allowing aggregate metrics for that page set.
  _PAGES_WITHOUT_SCROLL_GESTURE_BLACKLIST = [
      'http://mobile-news.sandbox.google.com/news/pt0']

  test = smoothness.Smoothness

  @classmethod
  def Name(cls):
    return 'smoothness'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    del is_first_result  # unused
    if (value.name == 'first_gesture_scroll_update_latency' and
        value.page.url in cls._PAGES_WITHOUT_SCROLL_GESTURE_BLACKLIST and
        value.values is None):
      return False
    return True


@benchmark.Owner(emails=['vmiura@chromium.org'])
class SmoothnessTop25(_Smoothness):
  """Measures rendering statistics while scrolling down the top 25 web pages.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks
  """
  page_set = page_sets.Top25SmoothPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.top_25_smooth'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/597656
    if (possible_browser.browser_type == 'reference' and
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X'):
      return True
    # http://crbug.com/650762
    if (possible_browser.browser_type == 'reference' and
        possible_browser.platform.GetOSName() == 'win'):
      return True
    return False


@benchmark.Owner(emails=['senorblanco@chromium.org'])
class SmoothnessToughFiltersCases(_Smoothness):
  """Measures frame rate and a variety of other statistics.

  Uses a selection of pages making use of SVG and CSS Filter Effects.
  """
  page_set = page_sets.ToughFiltersCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_filters_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/616520
    if (cls.IsSvelte(possible_browser) and
        possible_browser.browser_type == 'reference'):
      return True
    # http://crbug.com/624032
    if possible_browser.platform.GetDeviceTypeName() == 'Nexus 6':
      return True
    return False


@benchmark.Owner(emails=['senorblanco@chromium.org'])
class SmoothnessToughPathRenderingCases(_Smoothness):
  """Tests a selection of pages with SVG and 2D Canvas paths.

  Measures frame rate and a variety of other statistics.  """
  page_set = page_sets.ToughPathRenderingCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_path_rendering_cases'


@benchmark.Disabled('android')  # crbug.com/526901
@benchmark.Disabled('linux')  # crbug.com/715607
@benchmark.Owner(emails=['junov@chromium.org'])
class SmoothnessToughCanvasCases(_Smoothness):
  """Measures frame rate and a variety of other statistics.

  Uses a selection of pages making use of the 2D Canvas API.
  """
  page_set = page_sets.ToughCanvasCasesPageSet

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs('--enable-experimental-canvas-features')

  @classmethod
  def Name(cls):
    return 'smoothness.tough_canvas_cases'


@benchmark.Disabled('android')  # crbug.com/373812
@benchmark.Disabled('win-reference')  # crbug.com/612810
@benchmark.Owner(emails=['kbr@chromium.org', 'zmo@chromium.org'])
class SmoothnessToughWebGLCases(_Smoothness):
  page_set = page_sets.ToughWebglCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_webgl_cases'


@benchmark.Disabled('win') # http://crbug.com/692663
@benchmark.Disabled('android-webview')  # http://crbug.com/653933
@benchmark.Owner(emails=['kbr@chromium.org', 'zmo@chromium.org'])
class SmoothnessMaps(perf_benchmark.PerfBenchmark):
  page_set = page_sets.MapsPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.maps'


@benchmark.Disabled('android',
                    'mac')     # crbug.com/567802
@benchmark.Owner(emails=['ssid@chromium.org'])
class SmoothnessKeyDesktopMoveCases(_Smoothness):
  page_set = page_sets.KeyDesktopMoveCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.key_desktop_move_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetOSName() == 'win')


@benchmark.Enabled('android')
@benchmark.Owner(emails=['vmiura@chromium.org', 'tdresser@chromium.org'])
class SmoothnessKeyMobileSites(_Smoothness):
  """Measures rendering statistics while scrolling down the key mobile sites.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks
  """
  page_set = page_sets.KeyMobileSitesSmoothPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.key_mobile_sites_smooth'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')

@benchmark.Disabled('android')  # crbug.com/589580
@benchmark.Disabled('android-reference')  # crbug.com/588786
@benchmark.Disabled('mac')  # crbug.com/563615
@benchmark.Owner(emails=['alancutter@chromium.org'])
class SmoothnessToughAnimationCases(_Smoothness):
  page_set = page_sets.ToughAnimationCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_animation_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/595737
    # This test is flaky on low-end windows machine.
    return (possible_browser.platform.GetOSName() == 'win' and
            multiprocessing.cpu_count() <= 2)


@benchmark.Enabled('android')
@benchmark.Owner(emails=['ajuma@chromium.org'])
class SmoothnessKeySilkCases(_Smoothness):
  """Measures rendering statistics for the key silk cases without GPU
  rasterization.
  """
  page_set = page_sets.KeySilkCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.key_silk_cases'

  def CreateStorySet(self, options):
    stories = super(SmoothnessKeySilkCases, self).CreateStorySet(options)
    # Page26 (befamous) is too noisy to be useful; crbug.com/461127
    to_remove = [story for story in stories
                 if isinstance(story, page_sets.key_silk_cases.Page26)]
    for story in to_remove:
      stories.RemoveStory(story)
    return stories


@benchmark.Enabled('android')
@benchmark.Owner(emails=['vmiura@chromium.org'])
class SmoothnessGpuRasterizationTop25(_Smoothness):
  """Measures rendering statistics for the top 25 with GPU rasterization.
  """
  tag = 'gpu_rasterization'
  page_set = page_sets.Top25SmoothPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization.top_25_smooth'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')


# Although GPU rasterization is enabled on Mac, it is blacklisted for certain
# path cases, so it is still valuable to run both the GPU and non-GPU versions
# of this benchmark on Mac.
@benchmark.Owner(emails=['senorblanco@chromium.org'])
class SmoothnessGpuRasterizationToughPathRenderingCases(_Smoothness):
  """Tests a selection of pages with SVG and 2D canvas paths with GPU
  rasterization.
  """
  tag = 'gpu_rasterization'
  page_set = page_sets.ToughPathRenderingCasesPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization.tough_path_rendering_cases'


# With GPU Raster enabled on Mac, there's no reason to run this benchmark in
# addition to SmoothnessFiltersCases.
@benchmark.Disabled('mac')
@benchmark.Owner(emails=['senorblanco@chromium.org'])
class SmoothnessGpuRasterizationFiltersCases(_Smoothness):
  """Tests a selection of pages with SVG and CSS filter effects with GPU
  rasterization.
  """
  tag = 'gpu_rasterization'
  page_set = page_sets.ToughFiltersCasesPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization.tough_filters_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/616540
    return (cls.IsSvelte(possible_browser) and
            possible_browser.browser_type == 'reference')


@benchmark.Enabled('android')
@benchmark.Owner(emails=['tdresser@chromium.org', 'rbyers@chromium.org'])
class SmoothnessSyncScrollKeyMobileSites(_Smoothness):
  """Measures rendering statistics for the key mobile sites with synchronous
  (main thread) scrolling.
  """
  tag = 'sync_scroll'
  page_set = page_sets.KeyMobileSitesSmoothPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForSyncScrolling(options)

  @classmethod
  def Name(cls):
    return 'smoothness.sync_scroll.key_mobile_sites_smooth'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')


@benchmark.Enabled('android')
@benchmark.Owner(emails=['vmiura@chromium.org'])
class SmoothnessSimpleMobilePages(_Smoothness):
  """Measures rendering statistics for simple mobile sites page set.
  """
  page_set = page_sets.SimpleMobileSitesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.simple_mobile_sites'


@benchmark.Disabled('all') # http://crbug.com/631015
@benchmark.Owner(emails=['bokan@chromium.org'])
class SmoothnessToughPinchZoomCases(_Smoothness):
  """Measures rendering statistics for pinch-zooming in the tough pinch zoom
  cases.
  """
  page_set = page_sets.AndroidToughPinchZoomCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_pinch_zoom_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return (
       # http://crbug.com/564008
       cls.IsSvelte(possible_browser) or
       # http://crbug.com/630701
       possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')


@benchmark.Enabled('mac')
@benchmark.Owner(emails=['ericrk@chromium.org'])
class SmoothnessDesktopToughPinchZoomCases(_Smoothness):
  """Measures rendering statistics for pinch-zooming in the tough pinch zoom
  cases. Uses lower zoom levels customized for desktop limits.
  """
  page_set = page_sets.DesktopToughPinchZoomCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.desktop_tough_pinch_zoom_cases'


# This benchmark runs only on android by it is disabled on android as well
# because of http://crbug.com/610021
# @benchmark.Enabled('android')
@benchmark.Disabled('all')
@benchmark.Owner(emails=['ericrk@chromium.org'])
class SmoothnessGpuRasterizationToughPinchZoomCases(_Smoothness):
  """Measures rendering statistics for pinch-zooming in the tough pinch zoom
  cases with GPU rasterization.
  """
  tag = 'gpu_rasterization'
  test = smoothness.Smoothness
  page_set = page_sets.AndroidToughPinchZoomCasesPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization.tough_pinch_zoom_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/564008


@benchmark.Enabled('android')
@benchmark.Owner(emails=['vmiura@chromium.org'])
class SmoothnessGpuRasterizationPolymer(_Smoothness):
  """Measures rendering statistics for the Polymer cases with GPU rasterization.
  """
  tag = 'gpu_rasterization'
  page_set = page_sets.PolymerPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization.polymer'


@benchmark.Owner(emails=['reveman@chromium.org'])
class SmoothnessToughScrollingCases(_Smoothness):
  page_set = page_sets.ToughScrollingCasesPageSet

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    del is_first_result  # unused
    # Only keep 'mean_pixels_approximated' and 'mean_pixels_checkerboarded'
    # metrics. (crbug.com/529331)
    return value.name in ('mean_pixels_approximated',
                          'mean_pixels_checkerboarded')

  @classmethod
  def Name(cls):
    return 'smoothness.tough_scrolling_cases'

@benchmark.Disabled('all')  # crbug.com/667489
@benchmark.Owner(emails=['ericrk@chromium.org'])
class SmoothnessGpuRasterizationToughScrollingCases(_Smoothness):
  tag = 'gpu_rasterization'
  test = smoothness.Smoothness
  page_set = page_sets.ToughScrollingCasesPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization.tough_scrolling_cases'


@benchmark.Disabled('android')  # http://crbug.com/531593
@benchmark.Disabled('win')  # http://crbug.com/652372
class SmoothnessToughImageDecodeCases(_Smoothness):
  page_set = page_sets.ToughImageDecodeCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_image_decode_cases'


@benchmark.Disabled('android')  # http://crbug.com/610015
@benchmark.Owner(emails=['cblume@chromium.org'])
class SmoothnessImageDecodingCases(_Smoothness):
  """Measures decoding statistics for jpeg images.
  """
  page_set = page_sets.ImageDecodingCasesPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)
    options.AppendExtraBrowserArgs('--disable-accelerated-jpeg-decoding')

  @classmethod
  def Name(cls):
    return 'smoothness.image_decoding_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/563974


@benchmark.Disabled('android')  # http://crbug.com/513699
@benchmark.Owner(emails=['cblume@chromium.org'])
class SmoothnessGpuImageDecodingCases(_Smoothness):
  """Measures decoding statistics for jpeg images with GPU rasterization.
  """
  tag = 'gpu_rasterization_and_decoding'
  page_set = page_sets.ImageDecodingCasesPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)
    # TODO(sugoi): Remove the following line once M41 goes stable
    options.AppendExtraBrowserArgs('--enable-accelerated-jpeg-decoding')

  @classmethod
  def Name(cls):
    return 'smoothness.gpu_rasterization_and_decoding.image_decoding_cases'


@benchmark.Enabled('android')
@benchmark.Owner(emails=['picksi@chromium.org'])
class SmoothnessPathologicalMobileSites(_Smoothness):
  """Measures task execution statistics while scrolling pathological sites.
  """
  page_set = page_sets.PathologicalMobileSitesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.pathological_mobile_sites'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/685342
    if possible_browser.platform.GetDeviceTypeName() == 'Nexus 7':
      return True
    return False


@benchmark.Owner(emails=['vmiura@chromium.org'])
class SmoothnessToughTextureUploadCases(_Smoothness):
  page_set = page_sets.ToughTextureUploadCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_texture_upload_cases'


@benchmark.Owner(emails=['skyostil@chromium.org'])
class SmoothnessToughAdCases(_Smoothness):
  """Measures rendering statistics while displaying advertisements."""
  page_set = page_sets.SyntheticToughAdCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_ad_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/555089

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    del is_first_result  # unused
    # These pages don't scroll so it's not necessary to measure input latency.
    return value.name != 'first_gesture_scroll_update_latency'


# http://crbug.com/522619 (mac/win)
# http://crbug.com/683247 (android/linux)
@benchmark.Disabled('win', 'mac', 'android', 'linux')
@benchmark.Owner(emails=['skyostil@chromium.org'])
class SmoothnessScrollingToughAdCases(_Smoothness):
  """Measures rendering statistics while scrolling advertisements."""
  page_set = page_sets.ScrollingToughAdCasesPageSet

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
    return (possible_browser.browser_type == 'reference' and
            possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')

  @classmethod
  def Name(cls):
    return 'smoothness.scrolling_tough_ad_cases'


@benchmark.Owner(emails=['skyostil@chromium.org'])
class SmoothnessToughWebGLAdCases(_Smoothness):
  """Measures rendering statistics while scrolling advertisements."""
  page_set = page_sets.SyntheticToughWebglAdCasesPageSet

  @classmethod
  def Name(cls):
    return 'smoothness.tough_webgl_ad_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/574485


@benchmark.Disabled('reference')  # crbug.com/549428
@benchmark.Owner(emails=['skyostil@chromium.org', 'brianderson@chromium.org'])
class SmoothnessToughSchedulingCases(_Smoothness):
  """Measures rendering statistics while interacting with pages that have
  challenging scheduling properties.

  https://docs.google.com/a/chromium.org/document/d/
      17yhE5Po9By0sCdM1yZT3LiUECaUr_94rQt9j-4tOQIM/view"""
  page_set = page_sets.ToughSchedulingCasesPageSet

  @classmethod
  def Name(cls):
    # This should be smoothness.tough_scheduling_cases but since the benchmark
    # has been named this way for long time, we keep the name as-is to avoid
    # data migration.
    return 'scheduler.tough_scheduling_cases'

# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The page cycler v2.

For details, see design doc:
https://docs.google.com/document/d/1EZQX-x3eEphXupiX-Hq7T4Afju5_sIdxPWYetj7ynd0
"""

from core import perf_benchmark
import page_sets

from telemetry import benchmark
from telemetry.page import cache_temperature
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement


class _PageCyclerV2(perf_benchmark.PerfBenchmark):
  options = {'pageset_repeat': 2}

  def CreateTimelineBasedMeasurementOptions(self):
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()

    # "blink.console" is used for marking ranges in
    # cache_temperature.MarkTelemetryInternal.
    cat_filter.AddIncludedCategory('blink.console')

    # "navigation" and "blink.user_timing" are needed to capture core
    # navigation events.
    cat_filter.AddIncludedCategory('navigation')
    cat_filter.AddIncludedCategory('blink.user_timing')

    # "loading" is needed for first-meaningful-paint computation.
    cat_filter.AddIncludedCategory('loading')

    # "toplevel" category is used to capture TaskQueueManager events
    # necessary to compute time-to-interactive.
    cat_filter.AddIncludedCategory('toplevel')

    tbm_options = timeline_based_measurement.Options(
        overhead_level=cat_filter)
    tbm_options.SetTimelineBasedMetrics(['loadingMetric'])
    return tbm_options

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # crbug.com/619254
    if possible_browser.browser_type == 'reference':
      return True

    # crbug.com/616781
    if (cls.IsSvelte(possible_browser) or
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X' or
        possible_browser.platform.GetDeviceTypeName() == 'AOSP on BullHead'):
      return True
    return False


class PageCyclerV2Typical25(_PageCyclerV2):
  """Page load time benchmark for a 25 typical web pages.

  Designed to represent typical, not highly optimized or highly popular web
  sites. Runs against pages recorded in June, 2014.
  """

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.typical_25'

  def CreateStorySet(self, options):
    return page_sets.Typical25PageSet(run_no_page_interactions=True,
        cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2IntlArFaHe(_PageCyclerV2):
  """Page load time for a variety of pages in Arabic, Farsi and Hebrew.

  Runs against pages recorded in April, 2013.
  """
  page_set = page_sets.IntlArFaHePageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.intl_ar_fa_he'

  def CreateStorySet(self, options):
    return page_sets.IntlArFaHePageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2IntlEsFrPtBr(_PageCyclerV2):
  """Page load time for a pages in Spanish, French and Brazilian Portuguese.

  Runs against pages recorded in April, 2013.
  """
  page_set = page_sets.IntlEsFrPtBrPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.intl_es_fr_pt-BR'

  def CreateStorySet(self, options):
    return page_sets.IntlEsFrPtBrPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2IntlHiRu(_PageCyclerV2):
  """Page load time benchmark for a variety of pages in Hindi and Russian.

  Runs against pages recorded in April, 2013.
  """
  page_set = page_sets.IntlHiRuPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.intl_hi_ru'

  def CreateStorySet(self, options):
    return page_sets.IntlHiRuPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2IntlJaZh(_PageCyclerV2):
  """Page load time benchmark for a variety of pages in Japanese and Chinese.

  Runs against pages recorded in April, 2013.
  """

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.intl_ja_zh'

  def CreateStorySet(self, options):
    return page_sets.IntlJaZhPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2IntlKoThVi(_PageCyclerV2):
  """Page load time for a variety of pages in Korean, Thai and Vietnamese.

  Runs against pages recorded in April, 2013.
  """
  page_set = page_sets.IntlKoThViPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.intl_ko_th_vi'

  def CreateStorySet(self, options):
    return page_sets.IntlKoThViPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2Top10Mobile(_PageCyclerV2):
  """Page load time benchmark for the top 10 mobile web pages.

  Runs against pages recorded in November, 2013.
  """

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.top_10_mobile'

  def CreateStorySet(self, options):
    return page_sets.Top10MobilePageSet(run_no_page_interactions=True,
        cache_temperatures=[
            cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2ToughLayoutCases(_PageCyclerV2):
  """Page loading for the slowest layouts observed in the Alexa top 1 million.

  Recorded in July 2013.
  """
  page_set = page_sets.ToughLayoutCasesPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.tough_layout_cases'

  def CreateStorySet(self, options):
    return page_sets.ToughLayoutCasesPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


@benchmark.Disabled('reference', 'android')
class PageCyclerV2BasicOopifIsolated(_PageCyclerV2):
  """ A benchmark measuring performance of out-of-process iframes. """
  page_set = page_sets.OopifBasicPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2_site_isolation.basic_oopif'

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--site-per-process'])

  def CreateStorySet(self, options):
    return page_sets.OopifBasicPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])


class PageCyclerV2BasicOopif(_PageCyclerV2):
  """ A benchmark measuring performance of the out-of-process iframes page
  set, without running in out-of-process iframes mode.. """
  page_set = page_sets.OopifBasicPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.basic_oopif'

  def CreateStorySet(self, options):
    return page_sets.OopifBasicPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])

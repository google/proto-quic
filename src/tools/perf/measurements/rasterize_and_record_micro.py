# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import time

from telemetry.core import exceptions
from telemetry.page import legacy_page_test
from telemetry.value import scalar


class RasterizeAndRecordMicro(legacy_page_test.LegacyPageTest):

  def __init__(self, start_wait_time=2, rasterize_repeat=100, record_repeat=100,
               timeout=120, report_detailed_results=False):
    super(RasterizeAndRecordMicro, self).__init__()
    self._chrome_branch_number = None
    self._start_wait_time = start_wait_time
    self._rasterize_repeat = rasterize_repeat
    self._record_repeat = record_repeat
    self._timeout = timeout
    self._report_detailed_results = report_detailed_results

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs([
        '--enable-impl-side-painting',
        '--enable-threaded-compositing',
        '--enable-gpu-benchmarking'
    ])

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    try:
      tab.WaitForDocumentReadyStateToBeComplete()
    except exceptions.TimeoutException:
      pass
    time.sleep(self._start_wait_time)

    # Enqueue benchmark
    tab.ExecuteJavaScript("""
        window.benchmark_results = {};
        window.benchmark_results.done = false;
        window.benchmark_results.id =
            chrome.gpuBenchmarking.runMicroBenchmark(
                "rasterize_and_record_benchmark",
                function(value) {
                  window.benchmark_results.done = true;
                  window.benchmark_results.results = value;
                }, {
                  "record_repeat_count": %i,
                  "rasterize_repeat_count": %i
                });
    """ % (self._record_repeat, self._rasterize_repeat))

    benchmark_id = tab.EvaluateJavaScript('window.benchmark_results.id')
    if not benchmark_id:
      raise legacy_page_test.MeasurementFailure(
          'Failed to schedule rasterize_and_record_micro')

    tab.WaitForJavaScriptExpression(
        'window.benchmark_results.done', self._timeout)

    data = tab.EvaluateJavaScript('window.benchmark_results.results')

    pixels_recorded = data['pixels_recorded']
    record_time = data['record_time_ms']
    pixels_rasterized = data['pixels_rasterized']
    rasterize_time = data['rasterize_time_ms']
    # TODO(schenney): Remove this workaround when reference builds get past
    # the change that adds this comment.
    if 'picture_memory_usage' in data:
      picture_memory_usage = data['picture_memory_usage']
    else:
      picture_memory_usage = 0

    results.AddValue(scalar.ScalarValue(
        results.current_page, 'pixels_recorded', 'pixels', pixels_recorded))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'pixels_rasterized', 'pixels', pixels_rasterized))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'rasterize_time', 'ms', rasterize_time))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'viewport_picture_size', 'bytes',
        picture_memory_usage))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'record_time', 'ms', record_time))

    record_time_sk_null_canvas = data['record_time_sk_null_canvas_ms']
    record_time_painting_disabled = data['record_time_painting_disabled_ms']
    # TODO(schenney): Remove this workaround when reference builds get past
    # the change that adds this comment.
    record_time_caching_disabled = \
        data.get('record_time_caching_disabled_ms', 0)
    # TODO(schenney): Remove this workaround when reference builds get past
    # the change that adds this comment.
    record_time_construction_disabled = \
        data.get('record_time_construction_disabled_ms', 0)
    # TODO(wangxianzhu): Remove this workaround when reference builds get past
    # the change that adds this comment.
    record_time_subsequence_caching_disabled = \
        data.get('record_time_subsequence_caching_disabled_ms', 0)
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'record_time_sk_null_canvas', 'ms',
        record_time_sk_null_canvas))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'record_time_painting_disabled', 'ms',
        record_time_painting_disabled))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'record_time_caching_disabled', 'ms',
        record_time_caching_disabled))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'record_time_construction_disabled', 'ms',
        record_time_construction_disabled))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'record_time_subsequence_caching_disabled', 'ms',
        record_time_subsequence_caching_disabled))

    if self._report_detailed_results:
      pixels_rasterized_with_non_solid_color = \
          data['pixels_rasterized_with_non_solid_color']
      pixels_rasterized_as_opaque = \
          data['pixels_rasterized_as_opaque']
      total_layers = data['total_layers']
      total_picture_layers = data['total_picture_layers']
      total_picture_layers_with_no_content = \
          data['total_picture_layers_with_no_content']
      total_picture_layers_off_screen = \
          data['total_picture_layers_off_screen']
      # TODO(schenney): Remove this workaround when reference builds get past
      # the change that adds this comment.
      if 'total_pictures_in_pile_size' in data:
        total_pictures_in_pile_size = data['total_pictures_in_pile_size']
      else:
        total_pictures_in_pile_size = 0

      results.AddValue(scalar.ScalarValue(
          results.current_page, 'total_size_of_pictures_in_piles', 'bytes',
          total_pictures_in_pile_size))
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'pixels_rasterized_with_non_solid_color',
          'pixels', pixels_rasterized_with_non_solid_color))
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'pixels_rasterized_as_opaque', 'pixels',
          pixels_rasterized_as_opaque))
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'total_layers', 'count', total_layers))
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'total_picture_layers', 'count',
          total_picture_layers))
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'total_picture_layers_with_no_content', 'count',
          total_picture_layers_with_no_content))
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'total_picture_layers_off_screen', 'count',
          total_picture_layers_off_screen))

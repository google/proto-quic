# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os

from telemetry.value import list_of_scalar_values
from telemetry.value import scalar

from metrics import Metric


class MediaMetric(Metric):
  """MediaMetric class injects and calls JS responsible for recording metrics.

  Default media metrics are collected for every media element in the page,
  such as decoded_frame_count, dropped_frame_count, decoded_video_bytes, and
  decoded_audio_bytes.
  """

  def __init__(self, tab):
    super(MediaMetric, self).__init__()
    with open(os.path.join(os.path.dirname(__file__), 'media.js')) as f:
      js = f.read()
      tab.ExecuteJavaScript(js)
    self._results = None
    self._skip_basic_metrics = False

  def Start(self, page, tab):
    """Create the media metrics for all media elements in the document."""
    if hasattr(page, 'skip_basic_metrics'):
      self._skip_basic_metrics = page.skip_basic_metrics
    tab.ExecuteJavaScript('window.__createMediaMetricsForDocument()')

  def Stop(self, page, tab):
    self._results = tab.EvaluateJavaScript('window.__getAllMetrics()')

  # Optional |exclude_metrics| args are not in base class Metric.
  # pylint: disable=arguments-differ
  def AddResults(self, tab, results, exclude_metrics=None):
    """Reports all recorded metrics as Telemetry perf results."""
    exclude_metrics = exclude_metrics or []
    trace_names = []
    for media_metric in self._results:
      trace_names.append(self._AddResultsForMediaElement(media_metric, results,
                                                         exclude_metrics))

    return '_'.join(trace_names) or tab.url

  def _AddResultsForMediaElement(self, media_metric, results, exclude_metrics):
    """Reports metrics for one media element.

    Media metrics contain an ID identifying the media element and values:
    media_metric = {
      'id': 'video_1',
      'metrics': {
          'time_to_play': 120,
          'decoded_bytes': 13233,
          ...
      }
    }
    """
    def AddOneResult(metric, unit):
      if metric in exclude_metrics:
        return

      metrics = media_metric['metrics']
      for m in metrics:
        if m.startswith(metric):
          special_label = m[len(metric):]
          trace_name = '%s.%s%s' % (metric, trace, special_label)
          if isinstance(metrics[m], list):
            results.AddValue(list_of_scalar_values.ListOfScalarValues(
                results.current_page, trace_name, unit,
                values=[float(v) for v in metrics[m]],
                important=True))
          else:
            results.AddValue(scalar.ScalarValue(
                results.current_page, trace_name, unit, value=float(metrics[m]),
                important=True))

    trace = media_metric['id']
    if not trace:
      logging.error('Metrics ID is missing in results.')
      return

    if not self._skip_basic_metrics:
      AddOneResult('buffering_time', 'ms')
      AddOneResult('decoded_audio_bytes', 'bytes')
      AddOneResult('decoded_video_bytes', 'bytes')
      AddOneResult('decoded_frame_count', 'frames')
      AddOneResult('dropped_frame_count', 'frames')
      AddOneResult('time_to_play', 'ms')

    AddOneResult('avg_loop_time', 'ms')
    AddOneResult('seek', 'ms')
    return trace

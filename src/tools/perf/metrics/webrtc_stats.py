# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import re

from telemetry.internal.util import camel_case
from telemetry.value import list_of_scalar_values

from metrics import Metric


INTERESTING_METRICS = {
    'googDecodeMs': {
        'units': 'ms',
        'description': 'Time spent decoding.',
    },
    'googMaxDecodeMs': {
        'units': 'ms',
        'description': 'Maximum time spent decoding one frame.',
    },
    'googAvgEncodeMs': {
        'units': 'ms',
        'description': 'Average time spent encoding one frame.'
    },
    'googRtt': {
        'units': 'ms',
        'description': 'Measured round-trip time.',
    },
    'googJitterReceived': {
        'units': 'ms',
        'description': 'Receive-side jitter in milliseconds.',
    },
    'googCaptureJitterMs': {
        'units': 'ms',
        'description': 'Capture device (audio/video) jitter.',
    },
    'googTargetDelayMs': {
        'units': 'ms',
        'description': 'The delay we are targeting.',
    },
    'googExpandRate': {
        'units': '%',
        'description': 'How much we have NetEQ-expanded the audio (0-100%)',
    },
    'googFrameRateReceived': {
        'units': 'fps',
        'description': 'Receive-side frames per second (video)',
    },
    'googFrameRateSent': {
        'units': 'fps',
        'description': 'Send-side frames per second (video)',
    },
    # Bandwidth estimation stats.
    'googAvailableSendBandwidth': {
        'units': 'bit/s',
        'description': 'How much send bandwidth we estimate we have.'
    },
    'googAvailableReceiveBandwidth': {
        'units': 'bit/s',
        'description': 'How much receive bandwidth we estimate we have.'
    },
    'googTargetEncBitrate': {
        'units': 'bit/s',
        'description': ('The target encoding bitrate we estimate is good to '
                        'aim for given our bandwidth estimates.')
    },
}


def SelectMetrics(particular_metrics):
  if not particular_metrics:
    return INTERESTING_METRICS

  # You can only select among the predefined interesting metrics.
  assert set(particular_metrics).issubset(INTERESTING_METRICS.keys())
  return {key: value for key, value in INTERESTING_METRICS.iteritems()
          if key in particular_metrics}


def GetReportKind(report):
  if 'audioInputLevel' in report or 'audioOutputLevel' in report:
    return 'audio'
  if 'googFrameRateSent' in report or 'googFrameRateReceived' in report:
    return 'video'
  if 'googAvailableSendBandwidth' in report:
    return 'bwe'

  logging.debug('Did not recognize report batch: %s.', report.keys())

  # There are other kinds of reports, such as transport types, which we don't
  # care about here. For these cases just return 'unknown' which will ignore the
  # report.
  return 'unknown'


def DistinguishAudioVideoOrBwe(report, stat_name):
  return GetReportKind(report) + '_' + stat_name


def StripAudioVideoBweDistinction(stat_name):
  return re.sub('^(audio|video|bwe)_', '', stat_name)


def SortStatsIntoTimeSeries(report_batches, selected_metrics):
  time_series = {}
  for report_batch in report_batches:
    for report in report_batch:
      for stat_name, value in report.iteritems():
        if stat_name not in selected_metrics:
          continue
        if GetReportKind(report) == 'unknown':
          continue
        full_stat_name = DistinguishAudioVideoOrBwe(report, stat_name)
        time_series.setdefault(full_stat_name, []).append(float(value))

  return time_series


def PrintSpecialMarkerValue(results):
  results.AddValue(list_of_scalar_values.ListOfScalarValues(
      results.current_page, 'peer_connection_5_not_logging_more_conns',
      '', [17], description=('This marker signifies we never log more '
                             'than 5 peer connections'),
      important=False))


class WebRtcStatisticsMetric(Metric):
  """Makes it possible to measure stats from peer connections."""

  def __init__(self, particular_metrics=None):
    super(WebRtcStatisticsMetric, self).__init__()
    self._all_reports = None
    self._selected_metrics = SelectMetrics(particular_metrics)

  def Start(self, page, tab):
    pass

  def Stop(self, page, tab):
    """Digs out stats from data populated by the javascript in webrtc_cases."""
    self._all_reports = tab.EvaluateJavaScript(
        'JSON.stringify(window.peerConnectionReports)')

  def AddResults(self, tab, results):
    if not self._all_reports:
      return

    reports = json.loads(self._all_reports)
    for i, report in enumerate(reports):
      time_series = SortStatsIntoTimeSeries(report, self._selected_metrics)

      # Only ever show stats for 5 peer connections, or it's going to look
      # insane in the results.
      if i > 5:
        PrintSpecialMarkerValue(results)
        return

      for stat_name, values in time_series.iteritems():
        stat_name_underscored = camel_case.ToUnderscore(stat_name)
        trace_name = 'peer_connection_%d_%s' % (i, stat_name_underscored)
        general_name = StripAudioVideoBweDistinction(stat_name)
        results.AddValue(list_of_scalar_values.ListOfScalarValues(
            results.current_page, trace_name,
            INTERESTING_METRICS[general_name]['units'], values,
            description=INTERESTING_METRICS[general_name]['description'],
            important=False))

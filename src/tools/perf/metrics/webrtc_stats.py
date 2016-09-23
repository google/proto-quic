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
    'packetsReceived': {
        'units': 'packets',
        'description': 'Packets received by the peer connection',
    },
    'packetsSent': {
        'units': 'packets',
        'description': 'Packets sent by the peer connection',
    },
    'googDecodeMs': {
        'units': 'ms',
        'description': 'Time spent decoding.',
    },
    'googMaxDecodeMs': {
        'units': 'ms',
        'description': 'Maximum time spent decoding one frame.',
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
    'googTransmitBitrate': {
        'units': 'bit/s',
        'description': 'The actual transmit bitrate.'
    },
}


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


def SortStatsIntoTimeSeries(report_batches):
  time_series = {}
  for report_batch in report_batches:
    for report in report_batch:
      for stat_name, value in report.iteritems():
        if stat_name not in INTERESTING_METRICS:
          continue
        if GetReportKind(report) == 'unknown':
          continue
        full_stat_name = DistinguishAudioVideoOrBwe(report, stat_name)
        time_series.setdefault(full_stat_name, []).append(float(value))

  return time_series


class WebRtcStatisticsMetric(Metric):
  """Makes it possible to measure stats from peer connections."""

  def __init__(self):
    super(WebRtcStatisticsMetric, self).__init__()
    self._all_reports = None

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
      time_series = SortStatsIntoTimeSeries(report)

      for stat_name, values in time_series.iteritems():
        stat_name_underscored = camel_case.ToUnderscore(stat_name)
        trace_name = 'peer_connection_%d_%s' % (i, stat_name_underscored)
        general_name = StripAudioVideoBweDistinction(stat_name)
        results.AddValue(list_of_scalar_values.ListOfScalarValues(
            results.current_page, trace_name,
            INTERESTING_METRICS[general_name]['units'], values,
            description=INTERESTING_METRICS[general_name]['description'],
            important=False))

# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.testing import simple_mock

from metrics import webrtc_stats


SAMPLE_JSON = '''
[[
   [
      {
         "googFrameHeightInput":"480",
         "googFrameWidthInput":"640",
         "googFrameRateSent": "23",
         "packetsLost":"-1",
         "googRtt":"19",
         "packetsSent":"1",
         "bytesSent":"0"
      },
      {
         "audioInputLevel":"2048",
         "googRtt":"20",
         "googCodecName":"opus",
         "packetsSent":"4",
         "bytesSent":"0"
      }
   ],
   [
      {
         "googFrameHeightInput":"480",
         "googFrameWidthInput":"640",
         "googFrameRateSent": "21",
         "packetsLost":"-1",
         "googRtt":"18",
         "packetsSent":"8",
         "bytesSent":"6291"
      },
      {
         "audioInputLevel":"1878",
         "googRtt":"17",
         "googCodecName":"opus",
         "packetsSent":"16",
         "bytesSent":"634"
      }
   ],
   [
      {
          "googAvailableSendBandwidth":"30000",
          "googAvailableRecvBandwidth":"12345",
          "googTargetEncBitrate":"10000"
      }
  ]
],
[
   [
      {
         "googFrameRateReceived": "23",
         "googDecodeMs":"0",
         "packetsReceived":"8",
         "googRenderDelayMs":"10",
         "googMaxDecodeMs":"0",
         "googRtt":"100"
      }
   ],
   [
      {
         "googFrameRateReceived": "23",
         "googDecodeMs":"14",
         "packetsReceived":"1234",
         "googRenderDelayMs":"102",
         "googMaxDecodeMs":"150",
         "googRtt":"101"
      }
   ],
   [
      {
          "googAvailableSendBandwidth":"40000",
          "googAvailableRecvBandwidth":"22345",
          "googTargetEncBitrate":"20000"
      }
  ]
]]
'''


class FakeResults(object):

  def __init__(self, current_page):
    self._received_values = []
    self._current_page = current_page

  @property
  def received_values(self):
    return self._received_values

  @property
  def current_page(self):
    return self._current_page

  def AddValue(self, value):
    self._received_values.append(value)


class WebRtcStatsUnittest(unittest.TestCase):

  def _RunMetricOnJson(self, json_to_return):
    stats_metric = webrtc_stats.WebRtcStatisticsMetric()

    tab = simple_mock.MockObject()
    page = simple_mock.MockObject()

    stats_metric.Start(page, tab)

    tab.ExpectCall('EvaluateJavaScript',
                   simple_mock.DONT_CARE).WillReturn(json_to_return)
    stats_metric.Stop(page, tab)

    page.url = simple_mock.MockObject()
    results = FakeResults(page)
    stats_metric.AddResults(tab, results)
    return results

  def testExtractsValuesAsTimeSeries(self):
    results = self._RunMetricOnJson(SAMPLE_JSON)

    self.assertTrue(results.received_values,
                    'Expected values for googDecodeMs and others, got none.')
    self.assertEqual(results.received_values[1].name,
                     'peer_connection_0_audio_goog_rtt')
    self.assertEqual(results.received_values[1].values,
                     [20.0, 17.0])
    self.assertEqual(results.received_values[7].name,
                     'peer_connection_1_video_goog_rtt')
    self.assertEqual(results.received_values[7].values,
                     [100.0, 101.0])

  def testExtractsInterestingMetricsOnly(self):
    results = self._RunMetricOnJson(SAMPLE_JSON)

    self.assertTrue(len(results.received_values) > 0)
    self.assertIn('peer_connection_0', results.received_values[0].name,
                  'The result should be a ListOfScalarValues instance with '
                  'a name <peer connection id>_<statistic>.')
    all_names = [value.name for value in results.received_values]
    self.assertIn('peer_connection_0_audio_goog_rtt', all_names)
    self.assertNotIn('peer_connection_1_audio_goog_rtt', all_names,
                     'Peer connection 1 does not have a goog-rtt in '
                     'the JSON above, unlike peer connection 0 which does.')
    self.assertIn('peer_connection_0_video_goog_rtt', all_names)
    self.assertIn('peer_connection_1_video_goog_rtt', all_names)
    # The audio_audio is intentional since the code distinguishes audio reports
    # from video reports (even though audio_input_level is quite obvious).
    self.assertNotIn('peer_connection_0_audio_audio_input_level', all_names,
                     'Input level is in the JSON for both connections but '
                     'should not be reported since it is not interesting.')
    self.assertNotIn('peer_connection_1_audio_audio_input_level', all_names)

  def testReturnsIfJsonIsEmpty(self):
    results = self._RunMetricOnJson('[]')
    self.assertFalse(results.received_values)

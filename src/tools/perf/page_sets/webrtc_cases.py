# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os

from telemetry import story
from telemetry.page import page as page_module


WEBRTC_TEST_PAGES_URL = 'https://test.webrtc.org/manual/'
WEBRTC_GITHUB_SAMPLES_URL = 'https://webrtc.github.io/samples/src/content/'
MEDIARECORDER_GITHUB_URL = 'https://rawgit.com/cricdecyan/mediarecorder/master/'


class WebrtcPage(page_module.Page):

  def __init__(self, url, page_set, name):
    super(WebrtcPage, self).__init__(
        url=url, page_set=page_set, name=name)

    with open(os.path.join(os.path.dirname(__file__),
                           'webrtc_track_peerconnections.js')) as javascript:
      self.script_to_evaluate_on_commit = javascript.read()


class Page1(WebrtcPage):
  """Why: Acquires a high definition (720p) local stream."""

  def __init__(self, page_set):
    super(Page1, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'getusermedia/resolution/',
        name='hd_local_stream_10s',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    action_runner.ClickElement('button[id="hd"]')
    action_runner.Wait(10)


class Page2(WebrtcPage):
  """Why: Sets up a local video-only WebRTC 720p call for 45 seconds."""

  def __init__(self, page_set):
    super(Page2, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'peerconnection/constraints/',
        name='720p_call_45s',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Action_Create_PeerConnection',
                                         repeatable=False):
      action_runner.ExecuteJavaScript('minWidthInput.value = 1280')
      action_runner.ExecuteJavaScript('maxWidthInput.value = 1280')
      action_runner.ExecuteJavaScript('minHeightInput.value = 720')
      action_runner.ExecuteJavaScript('maxHeightInput.value = 720')
      action_runner.ClickElement('button[id="getMedia"]')
      action_runner.Wait(2)
      action_runner.ClickElement('button[id="connect"]')
      action_runner.Wait(45)


class Page3(WebrtcPage):
  """Why: Transfer as much data as possible through a data channel in 20s."""

  def __init__(self, page_set):
    super(Page3, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'datachannel/datatransfer',
        name='30s_datachannel_transfer',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    # It won't have time to finish the 512 MB, but we're only interested in
    # cpu + memory anyway rather than how much data we manage to transfer.
    action_runner.ExecuteJavaScript('megsToSend.value = 512;')
    action_runner.ClickElement('button[id="sendTheData"]')
    action_runner.Wait(30)


class Page4(WebrtcPage):
  """Why: Sets up a WebRTC audio call with Opus."""

  def __init__(self, page_set):
    super(Page4, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'peerconnection/audio/?codec=OPUS',
        name='audio_call_opus_10s',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('codecSelector.value="OPUS";')
    action_runner.ClickElement('button[id="callButton"]')
    action_runner.Wait(10)


class Page5(WebrtcPage):
  """Why: Sets up a WebRTC audio call with G722."""

  def __init__(self, page_set):
    super(Page5, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'peerconnection/audio/?codec=G722',
        name='audio_call_g722_10s',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('codecSelector.value="G722";')
    action_runner.ClickElement('button[id="callButton"]')
    action_runner.Wait(10)


class Page6(WebrtcPage):
  """Why: Sets up a WebRTC audio call with PCMU."""

  def __init__(self, page_set):
    super(Page6, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'peerconnection/audio/?codec=PCMU',
        name='audio_call_pcmu_10s',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('codecSelector.value="PCMU";')
    action_runner.ClickElement('button[id="callButton"]')
    action_runner.Wait(10)


class Page7(WebrtcPage):
  """Why: Sets up a WebRTC audio call with iSAC 16K."""

  def __init__(self, page_set):
    super(Page7, self).__init__(
        url=WEBRTC_GITHUB_SAMPLES_URL + 'peerconnection/audio/?codec=ISAC_16K',
        name='audio_call_isac16k_10s',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('codecSelector.value="ISAC/16000";')
    action_runner.ClickElement('button[id="callButton"]')
    action_runner.Wait(10)


class Page8(WebrtcPage):
  """Why: Sets up a canvas capture stream connection to a peer connection."""

  def __init__(self, page_set):
    canvas_capure_html = 'canvascapture/canvas_capture_peerconnection.html'
    super(Page8, self).__init__(
        url=MEDIARECORDER_GITHUB_URL + canvas_capure_html,
        name='canvas_capture_peer_connection',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Action_Canvas_PeerConnection',
                                         repeatable=False):
      action_runner.ExecuteJavaScript('draw();')
      action_runner.ExecuteJavaScript('doCanvasCaptureAndPeerConnection();')
      action_runner.Wait(10)


class Page9(WebrtcPage):
  """Why: Sets up several peerconnections in the same page."""

  def __init__(self, page_set):
    super(Page9, self).__init__(
        url= WEBRTC_TEST_PAGES_URL + 'multiple-peerconnections/',
        name='multiple_peerconnections',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Action_Create_PeerConnection',
                                         repeatable=False):
      # Set the number of peer connections to create to 15.
      action_runner.ExecuteJavaScript(
          'document.getElementById("num-peerconnections").value=15')
      action_runner.ExecuteJavaScript(
          'document.getElementById("cpuoveruse-detection").checked=false')
      action_runner.ClickElement('button[id="start-test"]')
      action_runner.Wait(45)


class WebrtcGetusermediaPageSet(story.StorySet):
  """WebRTC tests for local getUserMedia: video capture and playback."""

  def __init__(self):
    super(WebrtcGetusermediaPageSet, self).__init__(
        archive_data_file='data/webrtc_getusermedia_cases.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(Page1(self))


class WebrtcStresstestPageSet(story.StorySet):
  """WebRTC stress-testing with multiple peer connections."""

  def __init__(self):
    super(WebrtcStresstestPageSet, self).__init__(
        archive_data_file='data/webrtc_stresstest_cases.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(Page9(self))


class WebrtcPeerconnectionPageSet(story.StorySet):
  """WebRTC tests for Real-time video and audio communication."""

  def __init__(self):
    super(WebrtcPeerconnectionPageSet, self).__init__(
        archive_data_file='data/webrtc_peerconnection_cases.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(Page2(self))


class WebrtcDatachannelPageSet(story.StorySet):
  """WebRTC tests for Real-time communication via the data channel."""

  def __init__(self):
    super(WebrtcDatachannelPageSet, self).__init__(
        archive_data_file='data/webrtc_datachannel_cases.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(Page3(self))


class WebrtcAudioPageSet(story.StorySet):
  """WebRTC tests for Real-time audio communication."""

  def __init__(self):
    super(WebrtcAudioPageSet, self).__init__(
        archive_data_file='data/webrtc_audio_cases.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(Page4(self))
    self.AddStory(Page5(self))
    self.AddStory(Page6(self))
    self.AddStory(Page7(self))


class WebrtcRenderingPageSet(story.StorySet):
  """WebRTC tests for video rendering."""

  def __init__(self):
    super(WebrtcRenderingPageSet, self).__init__(
        archive_data_file='data/webrtc_smoothness_cases.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    self.AddStory(Page2(self))
    self.AddStory(Page8(self))

# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import story
from telemetry.page import page as page_module


class WebrtcPage(page_module.Page):

  def __init__(self, url, page_set, name, tags):
    assert url.startswith('file://webrtc_cases/')
    super(WebrtcPage, self).__init__(
        url=url, page_set=page_set, name=name, tags=tags)


class GetUserMedia(WebrtcPage):
  """Why: Acquires a high definition (720p) local stream."""

  def __init__(self, page_set, tags):
    super(GetUserMedia, self).__init__(
        url='file://webrtc_cases/resolution.html',
        name='hd_local_stream_10s',
        page_set=page_set, tags=tags)

  def RunPageInteractions(self, action_runner):
    action_runner.ClickElement('button[id="hd"]')
    action_runner.Wait(10)


class VideoCall(WebrtcPage):
  """Why: Sets up a local video-only WebRTC 720p call for 45 seconds."""

  def __init__(self, page_set, tags):
    super(VideoCall, self).__init__(
        url='file://webrtc_cases/constraints.html',
        name='720p_call_45s',
        page_set=page_set, tags=tags)

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


class DataChannel(WebrtcPage):
  """Why: Transfer as much data as possible through a data channel in 20s."""

  def __init__(self, page_set, tags):
    super(DataChannel, self).__init__(
        url='file://webrtc_cases/datatransfer.html',
        name='30s_datachannel_transfer',
        page_set=page_set, tags=tags)

  def RunPageInteractions(self, action_runner):
    # It won't have time to finish the 512 MB, but we're only interested in
    # cpu + memory anyway rather than how much data we manage to transfer.
    action_runner.ExecuteJavaScript('megsToSend.value = 512;')
    action_runner.ClickElement('button[id="sendTheData"]')
    action_runner.Wait(30)


class AudioCall(WebrtcPage):
  """Why: Sets up a WebRTC audio call."""

  def __init__(self, page_set, codec, tags):
    super(AudioCall, self).__init__(
        url='file://webrtc_cases/audio.html?codec=%s' % codec,
        name='audio_call_%s_10s' % codec.lower(),
        page_set=page_set, tags=tags)
    self.codec = codec

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('codecSelector.value="%s";' % self.codec)
    action_runner.ClickElement('button[id="callButton"]')
    action_runner.Wait(10)

class CanvasCapturePeerConnection(WebrtcPage):
  """Why: Sets up a canvas capture stream connection to a peer connection."""

  def __init__(self, page_set, tags):
    super(CanvasCapturePeerConnection, self).__init__(
        url='file://webrtc_cases/canvas-capture.html',
        name='canvas_capture_peer_connection',
        page_set=page_set, tags=tags)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Action_Canvas_PeerConnection',
                                         repeatable=False):
      action_runner.ClickElement('button[id="startButton"]')
      action_runner.Wait(10)


class MultiplePeerConnections(WebrtcPage):
  """Why: Sets up several peer connections in the same page."""

  def __init__(self, page_set, tags):
    super(MultiplePeerConnections, self).__init__(
        url='file://webrtc_cases/multiple-peerconnections.html',
        name='multiple_peerconnections',
        page_set=page_set, tags=tags)

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


class WebrtcPageSet(story.StorySet):
  def __init__(self):
    super(WebrtcPageSet, self).__init__(
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(GetUserMedia(self, tags=['getusermedia']))
    self.AddStory(MultiplePeerConnections(self, tags=['stress']))
    self.AddStory(VideoCall(self, tags=['peerconnection', 'smoothness']))
    self.AddStory(DataChannel(self, tags=['datachannel']))
    self.AddStory(CanvasCapturePeerConnection(self, tags=['smoothness']))
    # TODO(qyearsley, mcasas): Add webrtc.audio when http://crbug.com/468732
    # is fixed, or revert https://codereview.chromium.org/1544573002/ when
    # http://crbug.com/568333 is fixed.
    # self.AddStory(AudioCall(self, 'OPUS'))
    # self.AddStory(AudioCall(self, 'G772'))
    # self.AddStory(AudioCall(self, 'PCMU'))
    # self.AddStory(AudioCall(self, 'ISAC/1600'))

# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections


Tag = collections.namedtuple('Tag', ['name', 'description'])


# Below are tags that describe various aspect of system health stories.
# A story can have multiple tags. All the tags should be noun.

AUDIO_PLAYBACK = Tag(
    'audio-playback', 'Story has audio playing.')
CANVAS_ANIMATION = Tag(
    'canvas-animation', 'Story has animations that are implemented using '
    'html5 canvas.')
CSS_ANIMATION = Tag(
    'css-animation', 'Story has animations that are implemented using CSS.')
EXTENSION = Tag(
    'extension', 'Story has browser with extension installed.')
IMAGES = Tag(
    'images', 'Story has sites with heavy uses of images.')
INTERNATIONAL = Tag(
    'international', 'Story has navigations to websites with content in non '
    'English languages.')
JAVASCRIPT_HEAVY = Tag(
    'javascript-heavy', 'Story has navigations to websites with heavy usages '
    'of JavaScript. The story uses 20Mb+ memory for javascript and local '
    'run with "v8" category enabled also shows the trace has js slices across '
    'the whole run.')
SCROLL = Tag(
    'scroll', 'Story has scroll gestures & scroll animation.')
PINCH_ZOOM = Tag(
    'pinch-zoom', 'Story has pinch zoom gestures & pinch zoom animation.')
TABS_SWITCHING = Tag(
    'tabs-switching', 'Story has multi tabs and tabs switching action.')
VIDEO_PLAYBACK = Tag(
    'video-playback', 'Story has video playing.')
WEBGL = Tag(
    'webgl', 'Story has sites with heavy uses of WebGL.')
WEB_STORAGE = Tag(
    'web-storage', 'Story has sites with heavy uses of Web storage.')


def _ExtractAllTags():
  all_tag_names = set()
  all_tags = []
  # Collect all the tags defined in this module. Also assert that there is no
  # duplicate tag names.
  for obj in globals().values():
    if isinstance(obj, Tag):
      all_tags.append(obj)
      assert obj.name not in all_tag_names, 'Duplicate tag name: %s' % obj.name
      all_tag_names.add(obj.name)
  return all_tags


ALL_TAGS = _ExtractAllTags()

# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import json
import os
import random


def GetShuffledSafeUrls():
  """Returns a deterministic shuffling of safe urls.

  The profile generators access the urls in order, and the urls are grouped by
  domain. The shuffling reduces the load on external servers.
  """
  random.seed(0)
  url_list_copy = list(GetSafeUrls())
  random.shuffle(url_list_copy)
  return url_list_copy


def GetSafeUrls():
  """Returns a list of safe urls by loading them from a pre-generated file."""
  safe_url_dir = os.path.dirname(os.path.realpath(__file__))
  safe_url_path = os.path.join(safe_url_dir, "profile_safe_url_list.json")
  with open(safe_url_path, "r") as safe_url_file:
    return json.load(safe_url_file)

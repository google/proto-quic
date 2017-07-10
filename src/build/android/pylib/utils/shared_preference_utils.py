# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility functions for modifying an app's settings file using JSON."""

import json
import logging

from devil.android.sdk import shared_prefs


def ExtractSettingsFromJson(filepath):
  """Extracts the settings data from the given JSON file.

  Args:
    filepath: The path to the JSON file to read.

  Return:
    The data read from the JSON file with strings converted to Python strings.
  """
  # json.load() loads strings as unicode, which causes issues when trying
  # to edit string values in preference files, so convert to Python strings
  def unicode_to_str(data):
    if isinstance(data, dict):
      return {unicode_to_str(key): unicode_to_str(value)
              for key, value in data.iteritems()}
    elif isinstance(data, list):
      return [unicode_to_str(element) for element in data]
    elif isinstance(data, unicode):
      return data.encode('utf-8')
    return data

  with open(filepath) as prefs_file:
    return unicode_to_str(json.load(prefs_file))


def ApplySharedPreferenceSettings(device, settings):
  """Applies the given app settings to the given device.

  Modifies an installed app's settings by modifying its shared preference
  settings file. Provided settings data must be a list of settings dictionaries,
  where dictionaries are in the following format:
  {
    "package": "com.example.package",
    "filename": "AppSettingsFile.xml",
    "set": {
      "SomeBoolToSet": true,
      "SomeStringToSet": "StringValue",
    },
    "remove": [
      "list",
      "of",
      "keys",
      "to",
      "remove",
    ]
  }

  Example JSON files that can be read with ExtractSettingsFromJson and passed to
  this function are in //chrome/android/shared_preference_files/test/.

  Args:
    device: The devil DeviceUtils object for the device the settings will be
        applied to.
    settings: A list of settings dictionaries to apply.
  """
  for pref in settings:
    prefs = shared_prefs.SharedPrefs(device, pref['package'], pref['filename'])
    prefs.Load()
    for key in pref.get('remove', []):
      try:
        prefs.Remove(key)
      except KeyError:
        logging.warning("Attempted to remove non-existent key %s", key)
    for key, value in pref.get('set', {}).iteritems():
      if isinstance(value, bool):
        prefs.SetBoolean(key, value)
      elif isinstance(value, basestring):
        prefs.SetString(key, value)
      elif isinstance(value, long) or isinstance(value, int):
        prefs.SetLong(key, value)
      elif isinstance(value, list):
        prefs.SetStringSet(key, value)
      else:
        raise ValueError("Given invalid value type %s for key %s" % (
            str(type(value)), key))
    prefs.Commit()

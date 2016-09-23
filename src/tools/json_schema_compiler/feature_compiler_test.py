#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import feature_compiler
import unittest

class FeatureCompilerTest(unittest.TestCase):
  """Test the FeatureCompiler. Note that we test that the expected features are
  generated more thoroughly in features_generation_unittest.cc. And, of course,
  this is most exhaustively tested through Chrome's compilation process (if a
  feature fails to parse, the compile fails).
  These tests primarily focus on catching errors during parsing.
  """
  def _parseFeature(self, value):
    """Parses a feature from the given value and returns the result."""
    f = feature_compiler.Feature('alpha')
    f.Parse(value)
    return f

  def _hasError(self, f, error):
    """Asserts that |error| is present somewhere in the given feature's
    errors."""
    self.assertTrue(f.errors)
    self.assertNotEqual(-1, str(f.errors).find(error), str(f.errors))

  def setUp(self):
    feature_compiler.ENABLE_ASSERTIONS = False
    feature_compiler.STRINGS_TO_UNICODE = True

  def testFeature(self):
    # Test some basic feature parsing for a sanity check.
    f = self._parseFeature({
      'blacklist': ['aaa', 'bbb'],
      'channel': 'stable',
      'command_line_switch': 'switch',
      'component_extensions_auto_granted': False,
      'contexts': ['blessed_extension', 'blessed_web_page'],
      'default_parent': True,
      'dependencies': ['dependency1', 'dependency2'],
      'extension_types': ['extension'],
      'location': 'component',
      'internal': True,
      'matches': ['*://*/*'],
      'max_manifest_version': 1,
      'noparent': True,
      'platforms': ['mac', 'win'],
      'session_types': ['kiosk', 'regular'],
      'whitelist': ['zzz', 'yyy']
    })
    self.assertFalse(f.errors)

  def testInvalidAll(self):
    f = self._parseFeature({
      'channel': 'stable',
      'dependencies': 'all',
    })
    self._hasError(f, 'Illegal value: "all"')

  def testUnknownKeyError(self):
    f = self._parseFeature({
      'contexts': ['blessed_extension'],
      'channel': 'stable',
      'unknownkey': 'unknownvalue'
    })
    self._hasError(f, 'Unrecognized key')

  def testUnknownEnumValue(self):
    f = self._parseFeature({
      'contexts': ['blessed_extension', 'unknown_context'],
      'channel': 'stable'
    })
    self._hasError(f, 'Illegal value: "unknown_context"')

  def testImproperType(self):
    f = self._parseFeature({'min_manifest_version': '1'})
    self._hasError(f, 'Illegal value: "1"')

  def testImproperSubType(self):
    f = self._parseFeature({'dependencies': [1, 2, 3]})
    self._hasError(f, 'Illegal value: "1"')

  def testImproperValue(self):
    f = self._parseFeature({'noparent': False})
    self._hasError(f, 'Illegal value: "False"')

  def testApiFeaturesNeedContexts(self):
    f = self._parseFeature({'dependencies': 'alpha',
                            'extension_types': ['extension'],
                            'channel': 'trunk'})
    f.Validate('APIFeature')
    self._hasError(f, 'APIFeatures must specify at least one context')

  def testManifestFeaturesNeedExtensionTypes(self):
    f = self._parseFeature({'dependencies': 'alpha', 'channel': 'beta'})
    f.Validate('ManifestFeature')
    self._hasError(f,
                   'ManifestFeatures must specify at least one extension type')

  def testManifestFeaturesCantHaveContexts(self):
    f = self._parseFeature({'dependencies': 'alpha',
                            'channel': 'beta',
                            'extension_types': ['extension'],
                            'contexts': ['blessed_extension']})
    f.Validate('ManifestFeature')
    self._hasError(f, 'ManifestFeatures do not support contexts')

  def testPermissionFeaturesNeedExtensionTypes(self):
    f = self._parseFeature({'dependencies': 'alpha', 'channel': 'beta'})
    f.Validate('PermissionFeature')
    self._hasError(
        f, 'PermissionFeatures must specify at least one extension type')

  def testPermissionFeaturesCantHaveContexts(self):
    f = self._parseFeature({'dependencies': 'alpha',
                            'channel': 'beta',
                            'extension_types': ['extension'],
                            'contexts': ['blessed_extension']})
    f.Validate('PermissionFeature')
    self._hasError(f, 'PermissionFeatures do not support contexts')

  def testAllPermissionsNeedChannelOrDependencies(self):
    api_feature = self._parseFeature({'contexts': ['blessed_extension']})
    api_feature.Validate('APIFeature')
    self._hasError(
        api_feature, 'Features must specify either a channel or dependencies')
    permission_feature = self._parseFeature({'extension_types': ['extension']})
    permission_feature.Validate('PermissionFeature')
    self._hasError(permission_feature,
                   'Features must specify either a channel or dependencies')
    manifest_feature = self._parseFeature({'extension_types': ['extension']})
    manifest_feature.Validate('ManifestFeature')
    self._hasError(manifest_feature,
                   'Features must specify either a channel or dependencies')
    channel_feature = self._parseFeature({'contexts': ['blessed_extension'],
                                          'channel': 'trunk'})
    channel_feature.Validate('APIFeature')
    self.assertFalse(channel_feature.errors)
    dependency_feature = self._parseFeature(
                             {'contexts': ['blessed_extension'],
                              'dependencies': ['alpha']})
    dependency_feature.Validate('APIFeature')
    self.assertFalse(dependency_feature.errors)


if __name__ == '__main__':
  unittest.main()

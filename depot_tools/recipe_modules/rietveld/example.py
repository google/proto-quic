# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

DEPS = [
  'recipe_engine/path',
  'recipe_engine/properties',
  'recipe_engine/step',
  'rietveld',
]

def RunSteps(api):
  api.path['checkout'] = api.path['slave_build']
  api.rietveld.apply_issue('foo', 'bar', authentication='oauth2')
  api.rietveld.calculate_issue_root({'project': ['']})


def GenTests(api):
  yield (api.test('basic')
         + api.properties(issue=1,
                          patchset=1,
                          rietveld='http://review_tool.url')
         )

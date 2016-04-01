# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

DEPS = [
  'recipe_engine/path',
  'recipe_engine/platform',
  'recipe_engine/properties',
  'recipe_engine/python',
  'tryserver',
]


def RunSteps(api):
  api.path['checkout'] = api.path['slave_build']
  api.tryserver.maybe_apply_issue()
  api.tryserver.get_files_affected_by_patch()

  if api.tryserver.is_tryserver:
    api.tryserver.set_subproject_tag('v8')

  api.tryserver.set_patch_failure_tryjob_result()
  api.tryserver.set_compile_failure_tryjob_result()
  api.tryserver.set_test_failure_tryjob_result()
  api.tryserver.set_invalid_test_results_tryjob_result()

  with api.tryserver.set_failure_hash():
    api.python.failing_step('fail', 'foo')


def GenTests(api):
  yield (api.test('with_svn_patch') +
         api.properties(patch_url='svn://checkout.url'))

  yield (api.test('with_git_patch') +
         api.properties(
              patch_storage='git',
              patch_project='v8',
              patch_repo_url='http://patch.url/',
              patch_ref='johndoe#123.diff'))

  yield (api.test('with_rietveld_patch') +
         api.properties.tryserver())

  yield (api.test('with_wrong_patch') + api.platform('win', 32))

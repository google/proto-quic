# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine import recipe_api

class PresubmitApi(recipe_api.RecipeApi):
  def __call__(self, *args, **kwargs):
    """Return a presubmit step."""

    name = kwargs.pop('name', 'presubmit')

    kwargs.setdefault('env', {})
    kwargs['env'].setdefault('PATH', '%(PATH)s')
    kwargs['env']['PATH'] = self.m.path.pathsep.join([
        kwargs['env']['PATH'], str(self._module.PACKAGE_DIRECTORY)])

    return self.m.python(
        name, self.package_resource('presubmit_support.py'), list(args),
        **kwargs)

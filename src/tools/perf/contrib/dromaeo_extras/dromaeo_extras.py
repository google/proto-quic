# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import benchmark

from benchmarks import dromaeo


# pylint: disable=protected-access
_BaseDromaeoBenchmark = dromaeo._DromaeoBenchmark
# pylint: enable=protected-access


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibAttrJquery(_BaseDromaeoBenchmark):
  """Dromaeo JSLib attr jquery JavaScript benchmark.

  Tests setting and getting DOM node attributes using the jQuery JavaScript
  Library.
  """
  tag = 'jslibattrjquery'
  query_param = 'jslib-attr-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibattrjquery'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibAttrPrototype(_BaseDromaeoBenchmark):
  """Dromaeo JSLib attr prototype JavaScript benchmark.

  Tests setting and getting DOM node attributes using the jQuery JavaScript
  Library.
  """
  tag = 'jslibattrprototype'
  query_param = 'jslib-attr-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibattrprototype'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibEventJquery(_BaseDromaeoBenchmark):
  """Dromaeo JSLib event jquery JavaScript benchmark.

  Tests binding, removing, and triggering DOM events using the jQuery JavaScript
  Library.
  """
  tag = 'jslibeventjquery'
  query_param = 'jslib-event-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibeventjquery'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibEventPrototype(_BaseDromaeoBenchmark):
  """Dromaeo JSLib event prototype JavaScript benchmark.

  Tests binding, removing, and triggering DOM events using the Prototype
  JavaScript Library.
  """
  tag = 'jslibeventprototype'
  query_param = 'jslib-event-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibeventprototype'


# win-ref: http://crbug.com/598705
# android: http://crbug.com/503138
# linux: http://crbug.com/583075
@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibModifyJquery(_BaseDromaeoBenchmark):
  """Dromaeo JSLib modify jquery JavaScript benchmark.

  Tests creating and injecting DOM nodes into a document using the jQuery
  JavaScript Library.
  """
  tag = 'jslibmodifyjquery'
  query_param = 'jslib-modify-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibmodifyjquery'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibModifyPrototype(_BaseDromaeoBenchmark):
  """Dromaeo JSLib modify prototype JavaScript benchmark.

  Tests creating and injecting DOM nodes into a document using the Prototype
  JavaScript Library.
  """
  tag = 'jslibmodifyprototype'
  query_param = 'jslib-modify-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibmodifyprototype'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibStyleJquery(_BaseDromaeoBenchmark):
  """Dromaeo JSLib style jquery JavaScript benchmark.

  Tests getting and setting CSS information on DOM elements using the jQuery
  JavaScript Library.
  """
  tag = 'jslibstylejquery'
  query_param = 'jslib-style-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibstylejquery'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibStylePrototype(_BaseDromaeoBenchmark):
  """Dromaeo JSLib style prototype JavaScript benchmark.

  Tests getting and setting CSS information on DOM elements using the jQuery
  JavaScript Library.
  """
  tag = 'jslibstyleprototype'
  query_param = 'jslib-style-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibstyleprototype'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibTraverseJquery(_BaseDromaeoBenchmark):
  """Dromaeo JSLib traverse jquery JavaScript benchmark.


  Tests getting and setting CSS information on DOM elements using the Prototype
  JavaScript Library.
  """
  tag = 'jslibtraversejquery'
  query_param = 'jslib-traverse-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibtraversejquery'


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class DromaeoJslibTraversePrototype(_BaseDromaeoBenchmark):
  """Dromaeo JSLib traverse prototype JavaScript benchmark.

  Tests traversing a DOM structure using the jQuery JavaScript Library.
  """
  tag = 'jslibtraverseprototype'
  query_param = 'jslib-traverse-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibtraverseprototype'


class DromaeoCSSQueryJquery(_BaseDromaeoBenchmark):
  """Dromaeo CSS Query jquery JavaScript benchmark.

  Tests traversing a DOM structure using the Prototype JavaScript Library.
  """
  tag = 'cssqueryjquery'
  query_param = 'cssquery-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.cssqueryjquery'

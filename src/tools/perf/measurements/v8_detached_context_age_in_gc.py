# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from telemetry.page import legacy_page_test
from telemetry.value import histogram_util
from telemetry.value import scalar
from telemetry.value import skip

_NAME = 'V8.DetachedContextAgeInGC'
_UNITS = 'garbage_collections'
_DISPLAY_NAME = 'V8_DetachedContextAgeInGC'
_TYPE = histogram_util.RENDERER_HISTOGRAM
_DESCRIPTION = 'Number of GCs needed to collect detached context'


def _GetMaxDetachedContextAge(tab, data_start):
  data = histogram_util.GetHistogram(_TYPE, _NAME, tab)
  delta = histogram_util.SubtractHistogram(data, data_start)
  if not 'buckets' in delta:
    return
  buckets = json.loads(delta)['buckets']
  if buckets:
    return max(x.get('high', x['low']) for x in buckets)


class V8DetachedContextAgeInGC(legacy_page_test.LegacyPageTest):

  def __init__(self):
    super(V8DetachedContextAgeInGC, self).__init__()
    self._data_start = None

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--enable-stats-collection-bindings'])

  def DidNavigateToPage(self, page, tab):
    del page  # unused
    self._data_start = histogram_util.GetHistogram(_TYPE, _NAME, tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    # Trigger GC to get histogram data.
    # Seven GCs should be enough to collect any detached context.
    # If a detached context survives more GCs then there is a leak.
    MAX_AGE = 8
    for _ in xrange(MAX_AGE):
      tab.CollectGarbage()
    value = _GetMaxDetachedContextAge(tab, self._data_start)
    if value is None:
      results.AddValue(skip.SkipValue(
          results.current_page, 'No detached contexts'))
    else:
      results.AddValue(scalar.ScalarValue(
          results.current_page, _DISPLAY_NAME, _UNITS, value,
          description=_DESCRIPTION))

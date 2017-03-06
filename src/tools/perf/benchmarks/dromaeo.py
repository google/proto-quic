# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import math
import os

from core import perf_benchmark

from telemetry import benchmark
from telemetry import page as page_module
from telemetry.page import legacy_page_test
from telemetry import story
from telemetry.value import scalar

from metrics import power


class _DromaeoMeasurement(legacy_page_test.LegacyPageTest):

  def __init__(self):
    super(_DromaeoMeasurement, self).__init__()
    self._power_metric = None

  def CustomizeBrowserOptions(self, options):
    power.PowerMetric.CustomizeBrowserOptions(options)

  def WillStartBrowser(self, platform):
    self._power_metric = power.PowerMetric(platform)

  def DidNavigateToPage(self, page, tab):
    self._power_metric.Start(page, tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    tab.WaitForJavaScriptCondition(
        'window.document.getElementById("pause") &&' +
        'window.document.getElementById("pause").value == "Run"',
        timeout=120)

    # Start spying on POST request that will report benchmark results, and
    # intercept result data.
    tab.ExecuteJavaScript("""
        (function() {
          var real_jquery_ajax_ = window.jQuery;
          window.results_ = "";
          window.jQuery.ajax = function(request) {
            if (request.url == "store.php") {
              window.results_ = decodeURIComponent(request.data);
              window.results_ = window.results_.substring(
                window.results_.indexOf("=") + 1,
                window.results_.lastIndexOf("&"));
              real_jquery_ajax_(request);
            }
          };
        })();""")
    # Starts benchmark.
    tab.ExecuteJavaScript('window.document.getElementById("pause").click();')

    tab.WaitForJavaScriptCondition('!!window.results_', timeout=600)

    self._power_metric.Stop(page, tab)
    self._power_metric.AddResults(tab, results)

    score = json.loads(tab.EvaluateJavaScript('window.results_ || "[]"'))

    def Escape(k):
      chars = [' ', '.', '-', '/', '(', ')', '*']
      for c in chars:
        k = k.replace(c, '_')
      return k

    def AggregateData(container, key, value):
      if key not in container:
        container[key] = {'count': 0, 'sum': 0}
      container[key]['count'] += 1
      container[key]['sum'] += math.log(value)

    suffix = page.url[page.url.index('?') + 1:]

    def AddResult(name, value):
      important = False
      if name == suffix:
        important = True
      results.AddValue(scalar.ScalarValue(
          results.current_page, Escape(name), 'runs/s', value, important))

    aggregated = {}
    for data in score:
      AddResult('%s/%s' % (data['collection'], data['name']),
                data['mean'])

      top_name = data['collection'].split('-', 1)[0]
      AggregateData(aggregated, top_name, data['mean'])

      collection_name = data['collection']
      AggregateData(aggregated, collection_name, data['mean'])

    for key, value in aggregated.iteritems():
      AddResult(key, math.exp(value['sum'] / value['count']))


class _DromaeoBenchmark(perf_benchmark.PerfBenchmark):
  """A base class for Dromaeo benchmarks."""
  test = _DromaeoMeasurement

  @classmethod
  def Name(cls):
    return 'dromaeo'

  def CreateStorySet(self, options):
    """Makes a PageSet for Dromaeo benchmarks."""
    # Subclasses are expected to define class members called query_param and
    # tag.
    if not hasattr(self, 'query_param') or not hasattr(self, 'tag'):
      raise NotImplementedError('query_param or tag not in Dromaeo benchmark.')
    archive_data_file = '../page_sets/data/dromaeo.%s.json' % self.tag
    ps = story.StorySet(
        archive_data_file=archive_data_file,
        base_dir=os.path.dirname(os.path.abspath(__file__)),
        cloud_storage_bucket=story.PUBLIC_BUCKET)
    url = 'http://dromaeo.com?%s' % self.query_param
    ps.AddStory(page_module.Page(
        url, ps, ps.base_dir, make_javascript_deterministic=False))
    return ps


class DromaeoDomCoreAttr(_DromaeoBenchmark):
  """Dromaeo DOMCore attr JavaScript benchmark.

  Tests setting and getting DOM node attributes.
  """
  tag = 'domcoreattr'
  query_param = 'dom-attr'

  @classmethod
  def Name(cls):
    return 'dromaeo.domcoreattr'


class DromaeoDomCoreModify(_DromaeoBenchmark):
  """Dromaeo DOMCore modify JavaScript benchmark.

  Tests creating and injecting DOM nodes.
  """
  tag = 'domcoremodify'
  query_param = 'dom-modify'

  @classmethod
  def Name(cls):
    return 'dromaeo.domcoremodify'


class DromaeoDomCoreQuery(_DromaeoBenchmark):
  """Dromaeo DOMCore query JavaScript benchmark.

  Tests querying DOM elements in a document.
  """
  tag = 'domcorequery'
  query_param = 'dom-query'

  @classmethod
  def Name(cls):
    return 'dromaeo.domcorequery'


class DromaeoDomCoreTraverse(_DromaeoBenchmark):
  """Dromaeo DOMCore traverse JavaScript benchmark.

  Tests traversing a DOM structure.
  """
  tag = 'domcoretraverse'
  query_param = 'dom-traverse'

  @classmethod
  def Name(cls):
    return 'dromaeo.domcoretraverse'


class DromaeoJslibAttrJquery(_DromaeoBenchmark):
  """Dromaeo JSLib attr jquery JavaScript benchmark.

  Tests setting and getting DOM node attributes using the jQuery JavaScript
  Library.
  """
  tag = 'jslibattrjquery'
  query_param = 'jslib-attr-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibattrjquery'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/634055 (Android One).
    return cls.IsSvelte(possible_browser)

class DromaeoJslibAttrPrototype(_DromaeoBenchmark):
  """Dromaeo JSLib attr prototype JavaScript benchmark.

  Tests setting and getting DOM node attributes using the jQuery JavaScript
  Library.
  """
  tag = 'jslibattrprototype'
  query_param = 'jslib-attr-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibattrprototype'


class DromaeoJslibEventJquery(_DromaeoBenchmark):
  """Dromaeo JSLib event jquery JavaScript benchmark.

  Tests binding, removing, and triggering DOM events using the jQuery JavaScript
  Library.
  """
  tag = 'jslibeventjquery'
  query_param = 'jslib-event-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibeventjquery'


class DromaeoJslibEventPrototype(_DromaeoBenchmark):
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
@benchmark.Disabled('win-reference', 'android', 'linux')
class DromaeoJslibModifyJquery(_DromaeoBenchmark):
  """Dromaeo JSLib modify jquery JavaScript benchmark.

  Tests creating and injecting DOM nodes into a document using the jQuery
  JavaScript Library.
  """
  tag = 'jslibmodifyjquery'
  query_param = 'jslib-modify-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibmodifyjquery'


class DromaeoJslibModifyPrototype(_DromaeoBenchmark):
  """Dromaeo JSLib modify prototype JavaScript benchmark.

  Tests creating and injecting DOM nodes into a document using the Prototype
  JavaScript Library.
  """
  tag = 'jslibmodifyprototype'
  query_param = 'jslib-modify-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibmodifyprototype'


class DromaeoJslibStyleJquery(_DromaeoBenchmark):
  """Dromaeo JSLib style jquery JavaScript benchmark.

  Tests getting and setting CSS information on DOM elements using the jQuery
  JavaScript Library.
  """
  tag = 'jslibstylejquery'
  query_param = 'jslib-style-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibstylejquery'


class DromaeoJslibStylePrototype(_DromaeoBenchmark):
  """Dromaeo JSLib style prototype JavaScript benchmark.

  Tests getting and setting CSS information on DOM elements using the jQuery
  JavaScript Library.
  """
  tag = 'jslibstyleprototype'
  query_param = 'jslib-style-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibstyleprototype'


class DromaeoJslibTraverseJquery(_DromaeoBenchmark):
  """Dromaeo JSLib traverse jquery JavaScript benchmark.


  Tests getting and setting CSS information on DOM elements using the Prototype
  JavaScript Library.
  """
  tag = 'jslibtraversejquery'
  query_param = 'jslib-traverse-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibtraversejquery'


class DromaeoJslibTraversePrototype(_DromaeoBenchmark):
  """Dromaeo JSLib traverse prototype JavaScript benchmark.

  Tests traversing a DOM structure using the jQuery JavaScript Library.
  """
  tag = 'jslibtraverseprototype'
  query_param = 'jslib-traverse-prototype'

  @classmethod
  def Name(cls):
    return 'dromaeo.jslibtraverseprototype'


class DromaeoCSSQueryJquery(_DromaeoBenchmark):
  """Dromaeo CSS Query jquery JavaScript benchmark.

  Tests traversing a DOM structure using the Prototype JavaScript Library.
  """
  tag = 'cssqueryjquery'
  query_param = 'cssquery-jquery'

  @classmethod
  def Name(cls):
    return 'dromaeo.cssqueryjquery'

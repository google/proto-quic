# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import sys

from telemetry.value import histogram
from telemetry.value import histogram_util
from telemetry.value import scalar

from metrics import Metric


_HISTOGRAMS = [
    {
        'name': 'V8.MemoryExternalFragmentationTotal', 'units': 'percent',
        'display_name': 'V8_MemoryExternalFragmentationTotal',
        'type': histogram_util.RENDERER_HISTOGRAM,
        'description': 'Total external memory fragmentation after each GC in '
                       'percent.',
    },
    {
        'name': 'V8.MemoryHeapSampleTotalCommitted', 'units': 'kb',
        'display_name': 'V8_MemoryHeapSampleTotalCommitted',
        'type': histogram_util.RENDERER_HISTOGRAM,
        'description': 'The total size of committed memory used by V8 after '
                       'each GC in KB.'
    },
    {
        'name': 'V8.MemoryHeapSampleTotalUsed', 'units': 'kb',
        'display_name': 'V8_MemoryHeapSampleTotalUsed',
        'type': histogram_util.RENDERER_HISTOGRAM,
        'description': 'The total size of live memory used by V8 after each '
                       'GC in KB.',
    },
    {
        'name': 'V8.MemoryHeapSampleMaximumCommitted', 'units': 'kb',
        'display_name': 'V8_MemoryHeapSampleMaximumCommitted',
        'type': histogram_util.RENDERER_HISTOGRAM
    },
    {
        'name': 'Memory.RendererUsed', 'units': 'kb',
        'display_name': 'Memory_RendererUsed',
        'type': histogram_util.RENDERER_HISTOGRAM
    },
    {
        'name': 'Memory.BrowserUsed', 'units': 'kb',
        'display_name': 'Memory_BrowserUsed',
        'type': histogram_util.BROWSER_HISTOGRAM
    },
]


class MemoryMetric(Metric):
  """MemoryMetric gathers memory statistics from the browser object.

  This includes both per-page histogram stats, most about javascript
  memory usage, and overall memory stats from the system for the whole
  test run."""

  def __init__(self, browser):
    super(MemoryMetric, self).__init__()
    self._browser = browser
    start_memory_stats = self._browser.memory_stats
    self._start_commit_charge = None
    if 'SystemCommitCharge' in start_memory_stats:
      self._start_commit_charge = start_memory_stats['SystemCommitCharge']
    self._memory_stats = None
    self._histogram_start = dict()
    self._histogram_delta = dict()
    self._started = False

  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.AppendExtraBrowserArgs([
        '--enable-stats-collection-bindings',
        # For a hard-coded set of Google pages (such as GMail), we produce
        # custom memory histograms (V8.Something_gmail) instead of the generic
        # histograms (V8.Something), if we detect that a renderer is only
        # rendering this page and no other pages. For this test, we need to
        # disable histogram customizing, so that we get the same generic
        # histograms produced for all pages.
        '--disable-histogram-customizer'
    ])

  def Start(self, page, tab):
    """Start the per-page preparation for this metric.

    Here, this consists of recording the start value of all the histograms.
    """
    if not self._browser.supports_memory_metrics:
      logging.warning('Memory metrics not supported.')
      return

    self._started = True

    for h in _HISTOGRAMS:
      histogram_data = histogram_util.GetHistogram(
          h['type'], h['name'], tab)
      # Histogram data may not be available
      if not histogram_data:
        continue
      self._histogram_start[h['name']] = histogram_data

  def Stop(self, page, tab):
    """Prepare the results for this page.

    The results are the differences between the current histogram values
    and the values when Start() was called.
    """
    if not self._browser.supports_memory_metrics:
      return

    assert self._started, 'Must call Start() first'
    for h in _HISTOGRAMS:
      # Histogram data may not be available
      if h['name'] not in self._histogram_start:
        continue
      histogram_data = histogram_util.GetHistogram(
          h['type'], h['name'], tab)
      self._histogram_delta[h['name']] = histogram_util.SubtractHistogram(
          histogram_data, self._histogram_start[h['name']])

  # Optional argument trace_name is not in base class Metric.
  # pylint: disable=arguments-differ
  def AddResults(self, tab, results, trace_name=None):
    """Add results for this page to the results object."""
    if not self._browser.supports_memory_metrics:
      return

    assert self._histogram_delta, 'Must call Stop() first'
    for h in _HISTOGRAMS:
      # Histogram data may not be available
      if h['name'] not in self._histogram_start:
        continue
      results.AddValue(histogram.HistogramValue(
          results.current_page, h['display_name'], h['units'],
          raw_value_json=self._histogram_delta[h['name']], important=False,
          description=h.get('description')))
    self._memory_stats = self._browser.memory_stats
    if not self._memory_stats['Browser']:
      return
    AddResultsForProcesses(results, self._memory_stats,
                           metric_trace_name=trace_name)

    if self._start_commit_charge:
      end_commit_charge = self._memory_stats['SystemCommitCharge']
      commit_charge_difference = end_commit_charge - self._start_commit_charge
      results.AddValue(scalar.ScalarValue(
          results.current_page,
          'commit_charge.' + (trace_name or 'commit_charge'),
          'kb', commit_charge_difference, important=False,
          description='System commit charge (committed memory pages).'))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'processes.' + (trace_name or 'processes'),
        'count', self._memory_stats['ProcessCount'], important=False,
        description='Number of processes used by Chrome.'))


def AddResultsForProcesses(results, memory_stats, chart_trace_name='final',
                           metric_trace_name=None,
                           exclude_metrics=None):
  """Adds memory stats for browser, renderer and gpu processes.

  Args:
    results: A telemetry.results.PageTestResults object.
    memory_stats: System memory stats collected.
    chart_trace_name: Trace to identify memory metrics. Default is 'final'.
    metric_trace_name: Trace to identify the metric results per test page.
    exclude_metrics: List of memory metrics to exclude from results,
                     e.g. VM, WorkingSetSize, etc.
  """
  metric = 'resident_set_size'
  if sys.platform == 'win32':
    metric = 'working_set'

  exclude_metrics = exclude_metrics or {}

  def AddResultsForProcessTypes(process_types_memory, process_type_trace):
    """Add all results for a given set of process types.

    Args:
      process_types_memory: A list of process types, e.g. Browser, 'Renderer'.
      process_type_trace: The name of this set of process types in the output.
    """
    def AddResult(value_name_memory, value_name_trace, description):
      """Add a result for a given statistic.

      Args:
        value_name_memory: Name of some statistic, e.g. VM, WorkingSetSize.
        value_name_trace: Name of this statistic to be used in the output.
      """
      if value_name_memory in exclude_metrics:
        return
      if len(process_types_memory) > 1 and value_name_memory.endswith('Peak'):
        return
      values = []
      for process_type_memory in process_types_memory:
        stats = memory_stats[process_type_memory]
        if value_name_memory in stats:
          values.append(stats[value_name_memory])
      if values:
        if metric_trace_name:
          current_trace = '%s_%s' % (metric_trace_name, process_type_trace)
          chart_name = value_name_trace
        else:
          current_trace = '%s_%s' % (value_name_trace, process_type_trace)
          chart_name = current_trace
        results.AddValue(scalar.ScalarValue(
            results.current_page, '%s.%s' % (chart_name, current_trace), 'kb',
            sum(values) / 1024, important=False, description=description))

    AddResult('VM', 'vm_%s_size' % chart_trace_name,
              'Virtual Memory Size (address space allocated).')
    AddResult('WorkingSetSize', 'vm_%s_%s_size' % (metric, chart_trace_name),
              'Working Set Size (Windows) or Resident Set Size (other '
              'platforms).')
    AddResult('PrivateDirty', 'vm_private_dirty_%s' % chart_trace_name,
              'Private Dirty is basically the amount of RAM inside the '
              'process that can not be paged to disk (it is not backed by the '
              'same data on disk), and is not shared with any other '
              'processes. Another way to look at this is the RAM that will '
              'become available to the system when that process goes away '
              '(and probably quickly subsumed into caches and other uses of '
              'it).')
    AddResult('ProportionalSetSize',
              'vm_proportional_set_size_%s' % chart_trace_name,
              'The Proportional Set Size (PSS) number is a metric the kernel '
              'computes that takes into account memory sharing -- basically '
              'each page of RAM in a process is scaled by a ratio of the '
              'number of other processes also using that page. This way you '
              'can (in theory) add up the PSS across all processes to see '
              'the total RAM they are using, and compare PSS between '
              'processes to get a rough idea of their relative weight.')
    AddResult('SharedDirty', 'vm_shared_dirty_%s' % chart_trace_name,
              'Shared Dirty is the amount of RAM outside the process that can '
              'not be paged to disk, and is shared with other processes.')
    AddResult('VMPeak', 'vm_peak_size',
              'The peak Virtual Memory Size (address space allocated) usage '
              'achieved by the * process.')
    AddResult('WorkingSetSizePeak', '%s_peak_size' % metric,
              'Peak Working Set Size.')

  AddResultsForProcessTypes(['Browser'], 'browser')
  AddResultsForProcessTypes(['Renderer'], 'renderer')
  AddResultsForProcessTypes(['Gpu'], 'gpu')
  AddResultsForProcessTypes(['Browser', 'Renderer', 'Gpu'], 'total')

# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.value import scalar

from metrics import memory
from metrics import Metric


class SystemMemoryMetric(Metric):
  """SystemMemoryMetric gathers system memory statistic.

  This metric collects system memory stats per test.  It reports the difference
  (delta) in system memory starts from the start of the test to the end of it.
  """

  def __init__(self, browser):
    super(SystemMemoryMetric, self).__init__()
    self._browser = browser
    self._memory_stats_start = None
    self._memory_stats_end = None

  def Start(self, page, tab):
    """Start the per-page preparation for this metric.

    Records the system memory stats at this point.
    """
    self._memory_stats_start = self._browser.memory_stats

  def Stop(self, page, tab):
    """Prepare the results for this page.

    The results are the differences between the current system memory stats
    and the values when Start() was called.
    """
    assert self._memory_stats_start, 'Must call Start() first'
    self._memory_stats_end = self._browser.memory_stats

  # |trace_name| and |exclude_metrics| args are not in base class Metric.
  # pylint: disable=arguments-differ
  def AddResults(self, tab, results, trace_name=None, exclude_metrics=None):
    """Add results for this page to the results object.

    Reports the delta in memory stats between the start stats and the end stats
    (as *_delta metrics). It reports end memory stats in case no matching start
    memory stats exists.

    Args:
      trace_name: Trace name to identify the summary results for current page.
      exclude_metrics: List of memory metrics to exclude from results,
                       e.g. VM, VMPeak, etc. See AddResultsForProcesses().
    """
    assert self._memory_stats_end, 'Must call Stop() first'
    memory_stats = _SubtractMemoryStats(self._memory_stats_end,
                                        self._memory_stats_start)
    if not memory_stats['Browser']:
      return
    exclude_metrics = exclude_metrics or {}
    memory.AddResultsForProcesses(
        results, memory_stats,
        metric_trace_name=trace_name, chart_trace_name='delta',
        exclude_metrics=exclude_metrics)

    if 'SystemCommitCharge' not in exclude_metrics:
      results.AddValue(scalar.ScalarValue(
          results.current_page,
          'commit_charge_delta.%s' % (trace_name or 'commit_charge'), 'kb',
          memory_stats['SystemCommitCharge'], important=False))

    if 'ProcessCount' not in exclude_metrics:
      results.AddValue(scalar.ScalarValue(
          results.current_page,
          'processes_delta.%s' % (trace_name or 'processes'), 'count',
          memory_stats['ProcessCount'], important=False))


def _SubtractMemoryStats(end_memory_stats, start_memory_stats):
  """Computes the difference in memory usage stats.

  Each of the two stats arguments is a dict with the following format:
      {'Browser': {metric: value, ...},
       'Renderer': {metric: value, ...},
       'Gpu': {metric: value, ...},
       'ProcessCount': value,
       etc
      }
  The metrics can be VM, WorkingSetSize, ProportionalSetSize, etc depending on
  the platform/test.

  NOTE: The only metrics that are not subtracted from original are the *Peak*
  memory values.

  Returns:
    A dict of process type names (Browser, Renderer, etc.) to memory usage
    metrics between the end collected stats and the start collected stats.
  """
  memory_stats = {}
  end_memory_stats = end_memory_stats or {}
  start_memory_stats = start_memory_stats or {}

  for process_type in end_memory_stats:
    memory_stats[process_type] = {}
    end_process_memory = end_memory_stats[process_type]
    if not end_process_memory:
      continue

    # If a process has end stats without start stats then report the end stats.
    # For example, a GPU process that started just after media playback.
    if (process_type not in start_memory_stats or
        not start_memory_stats[process_type]):
      memory_stats[process_type] = end_process_memory
      continue

    if not isinstance(end_process_memory, dict):
      start_value = start_memory_stats[process_type] or 0
      memory_stats[process_type] = end_process_memory - start_value
    else:
      for metric in end_process_memory:
        end_value = end_process_memory[metric]
        start_value = start_memory_stats[process_type].get(metric, 0)
        if 'Peak' in metric:
          memory_stats[process_type][metric] = end_value
        else:
          memory_stats[process_type][metric] = end_value - start_value
  return memory_stats

# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Classes representing the monitoring interface for tasks or devices.

Usage:
  import argparse
  from infra_libs import ts_mon

  p = argparse.ArgumentParser()
  ts_mon.add_argparse_options(p)
  args = p.parse_args()  # Must contain info for Monitor (and optionally Target)
  ts_mon.process_argparse_options(args)

  # Will use the default Target set up via command line args:
  m = ts_mon.BooleanMetric('/my/metric/name', fields={'foo': 1, 'bar': 'baz'})
  m.set(True)

  # Use a custom Target:
  t = ts_mon.TaskTarget('service', 'job', 'region', 'host')  # or DeviceTarget
  m2 = ts_mon.GaugeMetric('/my/metric/name2', fields={'asdf': 'qwer'}, target=t)
  m2.set(5)

Library usage:
  from infra_libs.ts_mon import CounterMetric
  # No need to set up Monitor or Target, assume calling code did that.
  c = CounterMetric('/my/counter', fields={'source': 'mylibrary'})
  c.set(0)
  for x in range(100):
    c.increment()
"""

import datetime
import logging
import random
import threading
import time
import traceback

from infra_libs.ts_mon.common import errors
from infra_libs.ts_mon.common import metric_store
from infra_libs.ts_mon.protos.current import metrics_pb2
from infra_libs.ts_mon.protos.new import metrics_pb2 as new_metrics_pb2

# The maximum number of MetricsData messages to include in each HTTP request.
# MetricsCollections larger than this will be split into multiple requests.
METRICS_DATA_LENGTH_LIMIT = 500


class State(object):
  """Package-level state is stored here so that it is easily accessible.

  Configuration is kept in this one object at the global level so that all
  libraries in use by the same tool or service can all take advantage of the
  same configuration.
  """

  def __init__(self, store_ctor=None, target=None):
    """Optional arguments are for unit tests."""
    if store_ctor is None:  # pragma: no branch
      store_ctor = metric_store.InProcessMetricStore
    # The Monitor object that will be used to send all metrics.
    self.global_monitor = None
    # The Target object that will be paired with all metrics that don't supply
    # their own.
    self.target = target
    # The flush mode being used to control when metrics are pushed.
    self.flush_mode = None
    # A predicate to determine if metrics should be sent.
    self.flush_enabled_fn = lambda: True
    # The background thread that flushes metrics every
    # --ts-mon-flush-interval-secs seconds.  May be None if
    # --ts-mon-flush != 'auto' or --ts-mon-flush-interval-secs == 0.
    self.flush_thread = None
    # All metrics created by this application.
    self.metrics = {}
    # The MetricStore object that holds the actual metric values.
    self.store = store_ctor(self)
    # Cached time of the last flush. Useful mostly in AppEngine apps.
    self.last_flushed = datetime.datetime.utcfromtimestamp(0)
    # Metric name prefix
    self.metric_name_prefix = '/chrome/infra/'
    # Use the new proto schema
    self.use_new_proto = False

  def reset_for_unittest(self):
    self.metrics = {}
    self.last_flushed = datetime.datetime.utcfromtimestamp(0)
    self.store.reset_for_unittest()
    self.use_new_proto = False

state = State()


def flush():
  """Send all metrics that are registered in the application."""
  if not state.flush_enabled_fn():
    logging.debug('ts_mon: sending metrics is disabled.')
    return

  if not state.global_monitor or not state.target:
    raise errors.MonitoringNoConfiguredMonitorError(None)

  if state.use_new_proto:
    generator = _generate_proto_new
  else:
    generator = _generate_proto

  for proto in generator():
    state.global_monitor.send(proto)
  state.last_flushed = datetime.datetime.utcnow()


def _generate_proto_new():
  """Generate MetricsPayload for global_monitor.send()."""
  proto = new_metrics_pb2.MetricsPayload()

  # Key: Target, value: MetricsCollection.
  collections = {}

  # Key: (Target, metric name) tuple, value: MetricsDataSet.
  data_sets = {}

  count = 0
  error_count = 0
  for (target, metric, start_time, end_time, fields_values
       ) in state.store.get_all():
    for fields, value in fields_values.iteritems():
      if count >= METRICS_DATA_LENGTH_LIMIT:
        yield proto
        proto = new_metrics_pb2.MetricsPayload()
        collections.clear()
        data_sets.clear()
        count = 0

      if target not in collections:
        collections[target] = proto.metrics_collection.add()
        target._populate_target_pb_new(collections[target])
      collection = collections[target]

      key = (target, metric.name)
      new_data_set = None
      try:
        if key not in data_sets:
            new_data_set = new_metrics_pb2.MetricsDataSet()
            metric._populate_data_set(new_data_set, fields)

        data = new_metrics_pb2.MetricsData()
        metric._populate_data(data, start_time, end_time, fields, value)
      except errors.MonitoringError:
        logging.exception('Failed to serialize a metric.')
        error_count += 1
        continue

      # All required data protos have been successfully populated. Now we can
      # insert them in serialized proto and bookeeping data structures.
      if new_data_set is not None:
        collection.metrics_data_set.add().CopyFrom(new_data_set)
        data_sets[key] = collection.metrics_data_set[-1]
      data_sets[key].data.add().CopyFrom(data)
      count += 1

  if count > 0:
    yield proto

  if error_count:
    raise errors.MonitoringFailedToFlushAllMetricsError(error_count)


def _generate_proto():
  """Generate MetricsCollection for global_monitor.send()."""
  proto = metrics_pb2.MetricsCollection()

  error_count = 0
  for target, metric, start_time, _, fields_values in state.store.get_all():
    for fields, value in fields_values.iteritems():
      if len(proto.data) >= METRICS_DATA_LENGTH_LIMIT:
        yield proto
        proto = metrics_pb2.MetricsCollection()

      try:
        metrics_pb = metrics_pb2.MetricsData()
        metric.serialize_to(metrics_pb, start_time, fields, value, target)
      except errors.MonitoringError:
        error_count += 1
        logging.exception('Failed to serialize a metric.')
        continue

      proto.data.add().CopyFrom(metrics_pb)

  if len(proto.data) > 0:
    yield proto

  if error_count:
    raise errors.MonitoringFailedToFlushAllMetricsError(error_count)


def register(metric):
  """Adds the metric to the list of metrics sent by flush().

  This is called automatically by Metric's constructor.
  """
  # If someone is registering the same metric object twice, that's okay, but
  # registering two different metric objects with the same metric name is not.
  for m in state.metrics.values():
    if metric == m:
      state.metrics[metric.name] = metric
      return
  if metric.name in state.metrics:
    raise errors.MonitoringDuplicateRegistrationError(metric.name)

  state.metrics[metric.name] = metric


def unregister(metric):
  """Removes the metric from the list of metrics sent by flush()."""
  del state.metrics[metric.name]


def close():
  """Stops any background threads and waits for them to exit."""
  if state.flush_thread is not None:
    state.flush_thread.stop()


def reset_for_unittest(disable=False):
  state.reset_for_unittest()
  if disable:
    state.flush_enabled_fn = lambda: False


class _FlushThread(threading.Thread):
  """Background thread that flushes metrics on an interval."""

  def __init__(self, interval_secs, stop_event=None):
    super(_FlushThread, self).__init__(name='ts_mon')

    if stop_event is None:
      stop_event = threading.Event()

    self.daemon = True
    self.interval_secs = interval_secs
    self.stop_event = stop_event

  def _flush_and_log_exceptions(self):
    try:
      flush()
    except Exception:
      logging.exception('Automatic monitoring flush failed.')

  def run(self):
    # Jitter the first interval so tasks started at the same time (say, by cron)
    # on different machines don't all send metrics simultaneously.
    next_timeout = random.uniform(self.interval_secs / 2.0, self.interval_secs)

    while True:
      if self.stop_event.wait(next_timeout):
        return

      # Try to flush every N seconds exactly so rate calculations are more
      # consistent.
      start = time.time()
      self._flush_and_log_exceptions()
      flush_duration = time.time() - start
      next_timeout = self.interval_secs - flush_duration

      if next_timeout < 0:
        logging.warning(
            'Last monitoring flush took %f seconds (longer than '
            '--ts-mon-flush-interval-secs = %f seconds)',
            flush_duration, self.interval_secs)
        next_timeout = 0

  def stop(self):
    """Stops the background thread and performs a final flush."""

    self.stop_event.set()
    self.join()

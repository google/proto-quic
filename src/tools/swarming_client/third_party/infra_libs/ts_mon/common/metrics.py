# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Classes representing individual metrics that can be sent."""

import copy

from infra_libs.ts_mon.protos.current import metrics_pb2
from infra_libs.ts_mon.protos.new import metrics_pb2 as new_metrics_pb2

from infra_libs.ts_mon.common import distribution
from infra_libs.ts_mon.common import errors
from infra_libs.ts_mon.common import interface


MICROSECONDS_PER_SECOND = 1000000


class Metric(object):
  """Abstract base class for a metric.

  A Metric is an attribute that may be monitored across many targets. Examples
  include disk usage or the number of requests a server has received. A single
  process may keep track of many metrics.

  Note that Metric objects may be initialized at any time (for example, at the
  top of a library), but cannot be sent until the underlying Monitor object
  has been set up (usually by the top-level process parsing the command line).

  A Metric can actually store multiple values that are identified by a set of
  fields (which are themselves key-value pairs).  Fields can be passed to the
  set() or increment() methods to modify a particular value, or passed to the
  constructor in which case they will be used as the defaults for this Metric.

  The unit of measurement for Metric data can be specified with MetricsDataUnits
  when a Metric object is created:
  e.g., MetricsDataUnits.SECONDS, MetricsDataUnits.BYTES, and etc..,
  A full list of supported units can be found in the following protobuf file
  : infra_libs/ts_mon/protos/metrics.proto

  Do not directly instantiate an object of this class.
  Use the concrete child classes instead:
  * StringMetric for metrics with string value
  * BooleanMetric for metrics with boolean values
  * CounterMetric for metrics with monotonically increasing integer values
  * GaugeMetric for metrics with arbitrarily varying integer values
  * CumulativeMetric for metrics with monotonically increasing float values
  * FloatMetric for metrics with arbitrarily varying float values

  See http://go/inframon-doc for help designing and using your metrics.
  """

  def __init__(self, name, fields=None, description=None, units=None):
    """Create an instance of a Metric.

    Args:
      name (str): the file-like name of this metric
      fields (dict): a set of key-value pairs to be set as default metric fields
      description (string): help string for the metric. Should be enough to
                            know what the metric is about.
      units (int): the unit used to measure data for given
                   metric. Please use the attributes of MetricDataUnit to find
                   valid integer values for this argument.
    """
    self._name = name.lstrip('/')
    self._start_time = None
    fields = fields or {}
    if len(fields) > 7:
      raise errors.MonitoringTooManyFieldsError(self._name, fields)
    self._fields = fields
    self._normalized_fields = self._normalize_fields(self._fields)
    self._description = description
    self._units = units

    interface.register(self)

  @property
  def name(self):
    return self._name

  @property
  def start_time(self):
    return self._start_time

  def is_cumulative(self):
    raise NotImplementedError()

  def __eq__(self, other):
    return (self.name == other.name and
            self._fields == other._fields and
            type(self) == type(other))

  def unregister(self):
    interface.unregister(self)

  @staticmethod
  def _map_units_to_string(units):
    """Map MetricsDataUnits to the corresponding string according to:
       http://unitsofmeasure.org/ucum.html because that's what the new proto
       requires."""
    if units in _UNITS_TO_STRING:
      return _UNITS_TO_STRING[units]
    else:
      return '{unknown}'

  def _populate_data_set(self, data_set, fields):
    """Populate MetricsDataSet."""
    data_set.metric_name = '%s%s' % (interface.state.metric_name_prefix,
                                     self._name)
    data_set.description = self._description or ''
    data_set.annotations.unit = self._map_units_to_string(self._units)

    if self.is_cumulative():
      data_set.stream_kind = new_metrics_pb2.CUMULATIVE
    else:
      data_set.stream_kind = new_metrics_pb2.GAUGE

    self._populate_value_type(data_set)
    self._populate_field_descriptors(data_set, fields)

  def _populate_data(self, data, start_time, end_time, fields, value):
    """Populate a new metrics_pb2.MetricsData.

    Args:
      data_ (new_metrics_pb2.MetricsData): protocol buffer into
        which to populate the current metric values.
      start_time (int): timestamp in microseconds since UNIX epoch.
    """
    data.start_timestamp.seconds = int(start_time)
    data.end_timestamp.seconds = int(end_time)

    self._populate_fields_new(data, fields)
    self._populate_value_new(data, value)

  def serialize_to(self, metric_pb, start_time, fields, value, target):
    """Generate metrics_pb2.MetricsData messages for this metric.

    Args:
      metric_pb (metrics_pb2.MetricsData): protocol buffer into which
        to serialize the current metric values.
      start_time (int): timestamp in microseconds since UNIX epoch.
      target (Target): a Target to use.
    """

    metric_pb.metric_name_prefix = interface.state.metric_name_prefix
    metric_pb.name = self._name
    if self._description is not None:
      metric_pb.description = self._description
    if self._units is not None:
      metric_pb.units = self._units

    self._populate_value(metric_pb, value, start_time)
    self._populate_fields(metric_pb, fields)

    target._populate_target_pb(metric_pb)

  def _populate_field_descriptors(self, data_set, fields):
    """Populate `field_descriptor` in MetricsDataSet.

    Args:
      data_set (new_metrics_pb2.MetricsDataSet): a data set protobuf to
          populate
      fields (list of (key, value) tuples): normalized metric fields

    Raises:
      MonitoringInvalidFieldTypeError: if a field has a value of unknown type
    """
    field_type = new_metrics_pb2.MetricsDataSet.MetricFieldDescriptor
    for key, value in fields:
      descriptor = data_set.field_descriptor.add()
      descriptor.name = key
      if isinstance(value, basestring):
        descriptor.field_type = field_type.STRING
      elif isinstance(value, bool):
        descriptor.field_type = field_type.BOOL
      elif isinstance(value, int):
        descriptor.field_type = field_type.INT64
      else:
        raise errors.MonitoringInvalidFieldTypeError(self._name, key, value)

  def _populate_fields_new(self, data, fields):
    """Fill in the fields attribute of a metric protocol buffer.

    Args:
      metric (metrics_pb2.MetricsData): a metrics protobuf to populate
      fields (list of (key, value) tuples): normalized metric fields

    Raises:
      MonitoringInvalidFieldTypeError: if a field has a value of unknown type
    """
    for key, value in fields:
      field = data.field.add()
      field.name = key
      if isinstance(value, basestring):
        field.string_value = value
      elif isinstance(value, bool):
        field.bool_value = value
      elif isinstance(value, int):
        field.int64_value = value
      else:
        raise errors.MonitoringInvalidFieldTypeError(self._name, key, value)

  def _populate_fields(self, metric, fields):
    """Fill in the fields attribute of a metric protocol buffer.

    Args:
      metric (metrics_pb2.MetricsData): a metrics protobuf to populate
      fields (list of (key, value) tuples): normalized metric fields

    Raises:
      MonitoringInvalidFieldTypeError: if a field has a value of unknown type
    """
    for key, value in fields:
      field = metric.fields.add()
      field.name = key
      if isinstance(value, basestring):
        field.type = metrics_pb2.MetricsField.STRING
        field.string_value = value
      elif isinstance(value, bool):
        field.type = metrics_pb2.MetricsField.BOOL
        field.bool_value = value
      elif isinstance(value, int):
        field.type = metrics_pb2.MetricsField.INT
        field.int_value = value
      else:
        raise errors.MonitoringInvalidFieldTypeError(self._name, key, value)

  def _normalize_fields(self, fields):
    """Merges the fields with the default fields and returns something hashable.

    Args:
      fields (dict): A dict of fields passed by the user, or None.

    Returns:
      A tuple of (key, value) tuples, ordered by key.  This whole tuple is used
      as the key in the self._values dict to identify the cell for a value.

    Raises:
      MonitoringTooManyFieldsError: if there are more than seven metric fields
    """
    if fields is None:
      return self._normalized_fields

    all_fields = copy.copy(self._fields)
    all_fields.update(fields)

    if len(all_fields) > 7:
      raise errors.MonitoringTooManyFieldsError(self._name, all_fields)

    return tuple(sorted(all_fields.iteritems()))

  def _populate_value(self, metric, value, start_time):
    """Fill in the the data values of a metric protocol buffer.

    Args:
      metric (metrics_pb2.MetricsData): a metrics protobuf to populate
      value (see concrete class): the value of the metric to be set
      start_time (int): timestamp in microseconds since UNIX epoch.
    """
    raise NotImplementedError()

  def _populate_value_new(self, data, value):
    """Fill in the the data values of a metric protocol buffer.

    Args:
      data (metrics_pb2.MetricsData): a metrics protobuf to populate
      value (see concrete class): the value of the metric to be set
    """
    raise NotImplementedError()

  def _populate_value_type(self, data_set):
    """Fill in the the data values of a metric protocol buffer.

    Args:
      data_set (metrics_pb2.MetricsDataSet): a MetricsDataSet protobuf to
          populate
    """
    raise NotImplementedError()

  def set(self, value, fields=None, target_fields=None):
    """Set a new value for this metric. Results in sending a new value.

    The subclass should do appropriate type checking on value and then call
    self._set_and_send_value.

    Args:
      value (see concrete class): the value of the metric to be set
      fields (dict): additional metric fields to complement those on self
      target_fields (dict): overwrite some of the default target fields
    """
    raise NotImplementedError()

  def get(self, fields=None, target_fields=None):
    """Returns the current value for this metric.

    Subclasses should never use this to get a value, modify it and set it again.
    Instead use _incr with a modify_fn.
    """
    return interface.state.store.get(
        self.name, self._normalize_fields(fields), target_fields)

  def get_all(self):
    return interface.state.store.iter_field_values(self.name)

  def reset(self):
    """Clears the values of this metric.  Useful in unit tests.

    It might be easier to call ts_mon.reset_for_unittest() in your setUp()
    method instead of resetting every individual metric.
    """

    interface.state.store.reset_for_unittest(self.name)

  def _set(self, fields, target_fields, value, enforce_ge=False):
    interface.state.store.set(self.name, self._normalize_fields(fields),
                              target_fields, value, enforce_ge=enforce_ge)

  def _incr(self, fields, target_fields, delta, modify_fn=None):
    interface.state.store.incr(self.name, self._normalize_fields(fields),
                               target_fields, delta, modify_fn=modify_fn)


class StringMetric(Metric):
  """A metric whose value type is a string."""

  def _populate_value(self, metric, value, start_time):
    metric.string_value = value

  def _populate_value_new(self, data, value):
    data.string_value = value

  def _populate_value_type(self, data_set):
    data_set.value_type = new_metrics_pb2.STRING

  def set(self, value, fields=None, target_fields=None):
    if not isinstance(value, basestring):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)
    self._set(fields, target_fields, value)

  def is_cumulative(self):
    return False


class BooleanMetric(Metric):
  """A metric whose value type is a boolean."""

  def _populate_value(self, metric, value, start_time):
    metric.boolean_value = value

  def _populate_value_new(self, data, value):
    data.bool_value = value

  def _populate_value_type(self, data_set):
    data_set.value_type = new_metrics_pb2.BOOL

  def set(self, value, fields=None, target_fields=None):
    if not isinstance(value, bool):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)
    self._set(fields, target_fields, value)

  def is_cumulative(self):
    return False


class NumericMetric(Metric):  # pylint: disable=abstract-method
  """Abstract base class for numeric (int or float) metrics."""
  # TODO(agable): Figure out if there's a way to send units with these metrics.

  def increment(self, fields=None, target_fields=None):
    self._incr(fields, target_fields, 1)

  def increment_by(self, step, fields=None, target_fields=None):
    self._incr(fields, target_fields, step)


class CounterMetric(NumericMetric):
  """A metric whose value type is a monotonically increasing integer."""

  def __init__(self, name, fields=None, start_time=None, description=None,
               units=None):
    super(CounterMetric, self).__init__(
        name, fields=fields, description=description, units=units)
    self._start_time = start_time

  def _populate_value(self, metric, value, start_time):
    metric.counter = value
    metric.start_timestamp_us = int(start_time * MICROSECONDS_PER_SECOND)

  def _populate_value_new(self, data, value):
    data.int64_value = value

  def _populate_value_type(self, data_set):
    data_set.value_type = new_metrics_pb2.INT64

  def set(self, value, fields=None, target_fields=None):
    if not isinstance(value, (int, long)):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)
    self._set(fields, target_fields, value, enforce_ge=True)

  def increment_by(self, step, fields=None, target_fields=None):
    if not isinstance(step, (int, long)):
      raise errors.MonitoringInvalidValueTypeError(self._name, step)
    self._incr(fields, target_fields, step)

  def is_cumulative(self):
    return True


class GaugeMetric(NumericMetric):
  """A metric whose value type is an integer."""

  def _populate_value(self, metric, value, start_time):
    metric.gauge = value

  def _populate_value_new(self, data, value):
    data.int64_value = value

  def _populate_value_type(self, data_set):
    data_set.value_type = new_metrics_pb2.INT64

  def set(self, value, fields=None, target_fields=None):
    if not isinstance(value, (int, long)):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)
    self._set(fields, target_fields, value)

  def is_cumulative(self):
    return False


class CumulativeMetric(NumericMetric):
  """A metric whose value type is a monotonically increasing float."""

  def __init__(self, name, fields=None, start_time=None, description=None,
               units=None):
    super(CumulativeMetric, self).__init__(
        name, fields=fields, description=description, units=units)
    self._start_time = start_time

  def _populate_value(self, metric, value, start_time):
    metric.cumulative_double_value = value
    metric.start_timestamp_us = int(start_time * MICROSECONDS_PER_SECOND)

  def _populate_value_new(self, data, value):
    data.double_value = value

  def _populate_value_type(self, data_set):
    data_set.value_type = new_metrics_pb2.DOUBLE

  def set(self, value, fields=None, target_fields=None):
    if not isinstance(value, (float, int)):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)
    self._set(fields, target_fields, float(value), enforce_ge=True)

  def is_cumulative(self):
    return True


class FloatMetric(NumericMetric):
  """A metric whose value type is a float."""

  def _populate_value(self, metric, value, start_time):
    metric.noncumulative_double_value = value

  def _populate_value_new(self, metric, value):
    metric.double_value = value

  def _populate_value_type(self, data_set_pb):
    data_set_pb.value_type = new_metrics_pb2.DOUBLE

  def set(self, value, fields=None, target_fields=None):
    if not isinstance(value, (float, int)):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)
    self._set(fields, target_fields, float(value))

  def is_cumulative(self):
    return False


class DistributionMetric(Metric):
  """A metric that holds a distribution of values.

  By default buckets are chosen from a geometric progression, each bucket being
  approximately 1.59 times bigger than the last.  In practice this is suitable
  for many kinds of data, but you may want to provide a FixedWidthBucketer or
  GeometricBucketer with different parameters."""

  CANONICAL_SPEC_TYPES = {
      2: metrics_pb2.PrecomputedDistribution.CANONICAL_POWERS_OF_2,
      10**0.2: metrics_pb2.PrecomputedDistribution.CANONICAL_POWERS_OF_10_P_0_2,
      10: metrics_pb2.PrecomputedDistribution.CANONICAL_POWERS_OF_10,
  }

  def __init__(self, name, is_cumulative=True, bucketer=None, fields=None,
               start_time=None, description=None, units=None):
    super(DistributionMetric, self).__init__(
        name, fields=fields, description=description, units=units)
    self._start_time = start_time

    if bucketer is None:
      bucketer = distribution.GeometricBucketer()

    self._is_cumulative = is_cumulative
    self.bucketer = bucketer

  def _populate_value(self, metric, value, start_time):
    pb = metric.distribution

    pb.is_cumulative = self._is_cumulative
    if self._is_cumulative:
      metric.start_timestamp_us = int(start_time * MICROSECONDS_PER_SECOND)

    # Copy the bucketer params.
    if (value.bucketer.width == 0 and
        value.bucketer.growth_factor in self.CANONICAL_SPEC_TYPES):
      pb.spec_type = self.CANONICAL_SPEC_TYPES[value.bucketer.growth_factor]
    else:
      pb.spec_type = metrics_pb2.PrecomputedDistribution.CUSTOM_PARAMETERIZED
      pb.width = value.bucketer.width
      pb.growth_factor = value.bucketer.growth_factor
      pb.num_buckets = value.bucketer.num_finite_buckets

    # Copy the distribution bucket values.  Only include the finite buckets, not
    # the overflow buckets on each end.
    pb.bucket.extend(self._running_zero_generator(
        value.buckets.get(i, 0) for i in
        xrange(1, value.bucketer.total_buckets - 1)))

    # Add the overflow buckets if present.
    if value.bucketer.underflow_bucket in value.buckets:
      pb.underflow = value.buckets[value.bucketer.underflow_bucket]
    if value.bucketer.overflow_bucket in value.buckets:
      pb.overflow = value.buckets[value.bucketer.overflow_bucket]

    if value.count != 0:
      pb.mean = float(value.sum) / value.count

  def _populate_value_new(self, metric, value):
    pb = metric.distribution_value

    # Copy the bucketer params.
    if value.bucketer.width == 0:
      pb.exponential_buckets.growth_factor = value.bucketer.growth_factor
      pb.exponential_buckets.scale = 1.0
      pb.exponential_buckets.num_finite_buckets = (
          value.bucketer.num_finite_buckets)
    else:
      pb.linear_buckets.width = value.bucketer.width
      pb.linear_buckets.offset = 0.0
      pb.linear_buckets.num_finite_buckets = value.bucketer.num_finite_buckets

    # Copy the distribution bucket values.  Include the overflow buckets on
    # either end.
    pb.bucket_count.extend(
        value.buckets.get(i, 0) for i in
        xrange(0, value.bucketer.total_buckets))

    pb.count = value.count
    pb.mean = float(value.sum) / max(value.count, 1)

  def _populate_value_type(self, data_set_pb):
    data_set_pb.value_type = new_metrics_pb2.DISTRIBUTION

  @staticmethod
  def _running_zero_generator(iterable):
    """Compresses sequences of zeroes in the iterable into negative zero counts.

    For example an input of [1, 0, 0, 0, 2] is converted to [1, -3, 2].
    """

    count = 0

    for value in iterable:
      if value == 0:
        count += 1
      else:
        if count != 0:
          yield -count
          count = 0
        yield value

  def add(self, value, fields=None, target_fields=None):
    def modify_fn(dist, value):
      if dist == 0:
        dist = distribution.Distribution(self.bucketer)
      dist.add(value)
      return dist

    self._incr(fields, target_fields, value, modify_fn=modify_fn)

  def set(self, value, fields=None, target_fields=None):
    """Replaces the distribution with the given fields with another one.

    This only makes sense on non-cumulative DistributionMetrics.

    Args:
      value: A infra_libs.ts_mon.Distribution.
    """

    if self._is_cumulative:
      raise TypeError(
          'Cannot set() a cumulative DistributionMetric (use add() instead)')

    if not isinstance(value, distribution.Distribution):
      raise errors.MonitoringInvalidValueTypeError(self._name, value)

    self._set(fields, target_fields, value)

  def is_cumulative(self):
    raise NotImplementedError()  # Keep this class abstract.


class CumulativeDistributionMetric(DistributionMetric):
  """A DistributionMetric with is_cumulative set to True."""

  def __init__(self, name, bucketer=None, fields=None,
               description=None, units=None):
    super(CumulativeDistributionMetric, self).__init__(
        name,
        is_cumulative=True,
        bucketer=bucketer,
        fields=fields,
        description=description,
        units=units)

  def is_cumulative(self):
    return True


class NonCumulativeDistributionMetric(DistributionMetric):
  """A DistributionMetric with is_cumulative set to False."""

  def __init__(self, name, bucketer=None, fields=None,
               description=None, units=None):
    super(NonCumulativeDistributionMetric, self).__init__(
        name,
        is_cumulative=False,
        bucketer=bucketer,
        fields=fields,
        description=description,
        units=units)

  def is_cumulative(self):
    return False


class MetaMetricsDataUnits(type):
  """Metaclass to populate the enum values of metrics_pb2.MetricsData.Units."""
  def __new__(mcs, name, bases, attrs):
    attrs.update(metrics_pb2.MetricsData.Units.items())
    return super(MetaMetricsDataUnits, mcs).__new__(mcs, name, bases, attrs)


class MetricsDataUnits(object):
  """An enumeration class for units of measurement for Metrics data.
  See infra_libs/ts_mon/protos/metrics.proto for a full list of supported units.
  """
  __metaclass__ = MetaMetricsDataUnits

_UNITS_TO_STRING = {
    MetricsDataUnits.UNKNOWN_UNITS: '{unknown}',
    MetricsDataUnits.SECONDS: 's',
    MetricsDataUnits.MILLISECONDS: 'ms',
    MetricsDataUnits.MICROSECONDS: 'us',
    MetricsDataUnits.NANOSECONDS: 'ns',
    MetricsDataUnits.BITS: 'B',
    MetricsDataUnits.BYTES: 'By',
    MetricsDataUnits.KILOBYTES: 'kBy',
    MetricsDataUnits.MEGABYTES: 'MBy',
    MetricsDataUnits.GIGABYTES: 'GBy',
    MetricsDataUnits.KIBIBYTES: 'kiBy',
    MetricsDataUnits.MEBIBYTES: 'MiBy',
    MetricsDataUnits.GIBIBYTES: 'GiBy',
    MetricsDataUnits.AMPS: 'A',
    MetricsDataUnits.MILLIAMPS : 'mA',
    MetricsDataUnits.DEGREES_CELSIUS: 'Cel'
}

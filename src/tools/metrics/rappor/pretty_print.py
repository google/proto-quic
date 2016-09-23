#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'common'))
import models
import presubmit_util


# Model definitions for rappor.xml content
_SUMMARY_TYPE = models.TextNodeType('summary')

_NOISE_VALUES_TYPE = models.ObjectNodeType('noise-values',
    float_attributes=[
      'fake-prob',
      'fake-one-prob',
      'one-coin-prob',
      'zero-coin-prob',
    ])

_NOISE_LEVEL_TYPE = models.ObjectNodeType('noise-level',
    extra_newlines=(1, 1, 1),
    string_attributes=['name'],
    children=[
      models.ChildType('summary', _SUMMARY_TYPE, False),
      models.ChildType('values', _NOISE_VALUES_TYPE, False),
    ])

_NOISE_LEVELS_TYPE = models.ObjectNodeType('noise-levels',
    extra_newlines=(1, 1, 1),
    dont_indent=True,
    children=[
      models.ChildType('types', _NOISE_LEVEL_TYPE, True),
    ])

_PARAMETERS_TYPE = models.ObjectNodeType('parameters',
    int_attributes=[
      'num-cohorts',
      'bytes',
      'hash-functions',
    ],
    # Remove probabilities once all parsers process noise levels.
    float_attributes=[
      'fake-prob',
      'fake-one-prob',
      'one-coin-prob',
      'zero-coin-prob',
    ],
    string_attributes=[
      'reporting-level',
      'noise-level',
    ])

_RAPPOR_PARAMETERS_TYPE = models.ObjectNodeType('rappor-parameters',
    extra_newlines=(1, 1, 1),
    string_attributes=['name'],
    children=[
      models.ChildType('summary', _SUMMARY_TYPE, False),
      models.ChildType('parameters', _PARAMETERS_TYPE, False),
    ])

_RAPPOR_PARAMETERS_TYPES_TYPE = models.ObjectNodeType('rappor-parameter-types',
    extra_newlines=(1, 1, 1),
    dont_indent=True,
    children=[
      models.ChildType('types', _RAPPOR_PARAMETERS_TYPE, True),
    ])

_OWNER_TYPE = models.TextNodeType('owner', single_line=True)

_STRING_FIELD_TYPE = models.ObjectNodeType('string-field',
    extra_newlines=(1, 1, 0),
    string_attributes=['name'],
    children=[
      models.ChildType('summary', _SUMMARY_TYPE, False),
    ])

_FLAG_TYPE = models.TextNodeType('flag', single_line=True)

_FLAGS_FIELD_TYPE = models.ObjectNodeType('flags-field',
    extra_newlines=(1, 1, 0),
    string_attributes=['name', 'noise-level'],
    children=[
      models.ChildType('flags', _FLAG_TYPE, True),
      models.ChildType('summary', _SUMMARY_TYPE, False),
    ])

_UINT64_FIELD_TYPE = models.ObjectNodeType('uint64-field',
    extra_newlines=(1, 1, 0),
    string_attributes=['name', 'noise-level'],
    children=[
      models.ChildType('summary', _SUMMARY_TYPE, False),
    ])

_RAPPOR_METRIC_TYPE = models.ObjectNodeType('rappor-metric',
    extra_newlines=(1, 1, 1),
    string_attributes=['name', 'type'],
    children=[
      models.ChildType('owners', _OWNER_TYPE, True),
      models.ChildType('summary', _SUMMARY_TYPE, False),
      models.ChildType('strings', _STRING_FIELD_TYPE, True),
      models.ChildType('flags', _FLAGS_FIELD_TYPE, True),
      models.ChildType('uint64', _UINT64_FIELD_TYPE, True),
    ])

_RAPPOR_METRICS_TYPE = models.ObjectNodeType('rappor-metrics',
    extra_newlines=(1, 1, 1),
    dont_indent=True,
    children=[
      models.ChildType('metrics', _RAPPOR_METRIC_TYPE, True),
    ])

_RAPPOR_CONFIGURATION_TYPE = models.ObjectNodeType('rappor-configuration',
    extra_newlines=(1, 1, 1),
    dont_indent=True,
    children=[
      models.ChildType('noiseLevels', _NOISE_LEVELS_TYPE, False),
      models.ChildType('parameterTypes', _RAPPOR_PARAMETERS_TYPES_TYPE, False),
      models.ChildType('metrics', _RAPPOR_METRICS_TYPE, False),
    ])

RAPPOR_XML_TYPE = models.DocumentType(_RAPPOR_CONFIGURATION_TYPE)


def GetTypeNames(config):
  return set(p['name'] for p in config['parameterTypes']['types'])


def GetMissingOwnerErrors(metrics):
  """Check that all of the metrics have owners.

  Args:
    metrics: A list of rappor metric description objects.

  Returns:
    A list of errors about metrics missing owners.
  """
  missing_owners = [m for m in metrics if not m['owners']]
  return ['Rappor metric "%s" is missing an owner.' % metric['name']
          for metric in missing_owners]


def GetInvalidTypeErrors(type_names, metrics):
  """Check that all of the metrics have valid types.

  Args:
    type_names: The set of valid type names.
    metrics: A list of rappor metric description objects.

  Returns:
    A list of errors about metrics with invalid_types.
  """
  invalid_types = [m for m in metrics if m['type'] not in type_names]
  return ['Rappor metric "%s" has invalid type "%s"' % (
              metric['name'], metric['type'])
          for metric in invalid_types]


def GetErrors(config):
  """Check that rappor.xml passes some basic validation checks.

  Args:
    config: The parsed rappor.xml contents.

  Returns:
    A list of validation errors.
  """
  metrics = config['metrics']['metrics']
  type_names = GetTypeNames(config)
  return (GetMissingOwnerErrors(metrics) or
          GetInvalidTypeErrors(type_names, metrics))


def Cleanup(config):
  """Preform cleanup on description contents, such as sorting metrics.

  Args:
    config: The parsed rappor.xml contents.
  """
  types = config['parameterTypes']['types']
  types.sort(key=lambda x: x['name'])
  metrics = config['metrics']['metrics']
  metrics.sort(key=lambda x: x['name'])


def UpdateXML(original_xml):
  """Parse the original xml and return a pretty printed version.

  Args:
    original_xml: A string containing the original xml file contents.

  Returns:
    A Pretty printed xml string.
  """
  comments, config = RAPPOR_XML_TYPE.Parse(original_xml)

  errors = GetErrors(config)
  if errors:
    for error in errors:
      logging.error("%s", error)
    return None

  Cleanup(config)

  return RAPPOR_XML_TYPE.PrettyPrint(comments, config)


def main(argv):
  presubmit_util.DoPresubmitMain(argv, 'rappor.xml', 'rappor.old.xml',
                                 'pretty_print.py', UpdateXML)


if '__main__' == __name__:
  sys.exit(main(sys.argv))

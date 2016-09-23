# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Extract histogram names from the description XML file.

For more information on the format of the XML file, which is self-documenting,
see histograms.xml; however, here is a simple example to get you started. The
XML below will generate the following five histograms:

    HistogramTime
    HistogramEnum
    HistogramEnum_Chrome
    HistogramEnum_IE
    HistogramEnum_Firefox

<histogram-configuration>

<histograms>

<histogram name="HistogramTime" units="milliseconds">
  <summary>A brief description.</summary>
  <details>This is a more thorough description of this histogram.</details>
</histogram>

<histogram name="HistogramEnum" enum="MyEnumType">
  <summary>This histogram sports an enum value type.</summary>
</histogram>

</histograms>

<enums>

<enum name="MyEnumType">
  <summary>This is an example enum type, where the values mean little.</summary>
  <int value="1" label="FIRST_VALUE">This is the first value.</int>
  <int value="2" label="SECOND_VALUE">This is the second value.</int>
</enum>

</enums>

<histogram_suffixes_list>

<histogram_suffixes name="BrowserType">
  <suffix name="Chrome"/>
  <suffix name="IE"/>
  <suffix name="Firefox"/>
  <affected-histogram name="HistogramEnum"/>
</histogram_suffixes>

</histogram_suffixes_list>

</histogram-configuration>

"""

import copy
import logging
import xml.dom.minidom

OWNER_FIELD_PLACEHOLDER = (
    'Please list the metric\'s owners. Add more owner tags as needed.')

MAX_HISTOGRAM_SUFFIX_DEPENDENCY_DEPTH = 5


class Error(Exception):
  pass


def _JoinChildNodes(tag):
  """Join child nodes into a single text.

  Applicable to leafs like 'summary' and 'detail'.

  Args:
    tag: parent node

  Returns:
    a string with concatenated nodes' text representation.
  """
  return ''.join(c.toxml() for c in tag.childNodes).strip()


def _NormalizeString(s):
  """Replaces all whitespace sequences with a single space.

  The function properly handles multi-line strings.

  Args:
    s: The string to normalize, ('  \\n a  b c\\n d  ').

  Returns:
    The normalized string (a b c d).
  """
  return ' '.join(s.split())


def _NormalizeAllAttributeValues(node):
  """Recursively normalizes all tag attribute values in the given tree.

  Args:
    node: The minidom node to be normalized.

  Returns:
    The normalized minidom node.
  """
  if node.nodeType == xml.dom.minidom.Node.ELEMENT_NODE:
    for a in node.attributes.keys():
      node.attributes[a].value = _NormalizeString(node.attributes[a].value)

  for c in node.childNodes:
    _NormalizeAllAttributeValues(c)
  return node


def _ExpandHistogramNameWithSuffixes(suffix_name, histogram_name,
                                     histogram_suffixes_node):
  """Creates a new histogram name based on a histogram suffix.

  Args:
    suffix_name: The suffix string to apply to the histogram name. May be empty.
    histogram_name: The name of the histogram. May be of the form
      Group.BaseName or BaseName.
    histogram_suffixes_node: The histogram_suffixes XML node.

  Returns:
    A string with the expanded histogram name.

  Raises:
    Error: if the expansion can't be done.
  """
  if histogram_suffixes_node.hasAttribute('separator'):
    separator = histogram_suffixes_node.getAttribute('separator')
  else:
    separator = '_'

  if histogram_suffixes_node.hasAttribute('ordering'):
    ordering = histogram_suffixes_node.getAttribute('ordering')
  else:
    ordering = 'suffix'
  if ordering not in ['prefix', 'suffix']:
    logging.error('ordering needs to be prefix or suffix, value is %s',
                  ordering)
    raise Error()

  if not suffix_name:
    return histogram_name

  if ordering == 'suffix':
    return histogram_name + separator + suffix_name

  # For prefixes, the suffix_name is inserted between the "cluster" and the
  # "remainder", e.g. Foo.BarHist expanded with gamma becomes Foo.gamma_BarHist.
  sections = histogram_name.split('.')
  if len(sections) <= 1:
    logging.error(
        'Prefix Field Trial expansions require histogram names which include a '
        'dot separator. Histogram name is %s, and Field Trial is %s',
        histogram_name, histogram_suffixes_node.getAttribute('name'))
    raise Error()

  cluster = sections[0] + '.'
  remainder = '.'.join(sections[1:])
  return cluster + suffix_name + separator + remainder


def _ExtractEnumsFromXmlTree(tree):
  """Extract all <enum> nodes in the tree into a dictionary."""

  enums = {}
  have_errors = False

  last_name = None
  for enum in tree.getElementsByTagName('enum'):
    if enum.getAttribute('type') != 'int':
      logging.error('Unknown enum type %s', enum.getAttribute('type'))
      have_errors = True
      continue

    name = enum.getAttribute('name')
    if last_name is not None and name.lower() < last_name.lower():
      logging.error('Enums %s and %s are not in alphabetical order',
                    last_name, name)
      have_errors = True
    last_name = name

    if name in enums:
      logging.error('Duplicate enum %s', name)
      have_errors = True
      continue

    last_int_value = None
    enum_dict = {}
    enum_dict['name'] = name
    enum_dict['values'] = {}

    for int_tag in enum.getElementsByTagName('int'):
      value_dict = {}
      int_value = int(int_tag.getAttribute('value'))
      if last_int_value is not None and int_value < last_int_value:
        logging.error('Enum %s int values %d and %d are not in numerical order',
                      name, last_int_value, int_value)
        have_errors = True
      last_int_value = int_value
      if int_value in enum_dict['values']:
        logging.error('Duplicate enum value %d for enum %s', int_value, name)
        have_errors = True
        continue
      value_dict['label'] = int_tag.getAttribute('label')
      value_dict['summary'] = _JoinChildNodes(int_tag)
      enum_dict['values'][int_value] = value_dict

    summary_nodes = enum.getElementsByTagName('summary')
    if summary_nodes:
      enum_dict['summary'] = _NormalizeString(_JoinChildNodes(summary_nodes[0]))

    enums[name] = enum_dict

  return enums, have_errors


def _ExtractOwners(xml_node):
  """Extract all owners into a list from owner tag under |xml_node|."""
  owners = []
  for owner_node in xml_node.getElementsByTagName('owner'):
    owner_entry = _NormalizeString(_JoinChildNodes(owner_node))
    if OWNER_FIELD_PLACEHOLDER not in owner_entry:
      owners.append(owner_entry)
  return owners


def _ExtractHistogramsFromXmlTree(tree, enums):
  """Extract all <histogram> nodes in the tree into a dictionary."""

  # Process the histograms. The descriptions can include HTML tags.
  histograms = {}
  have_errors = False
  last_name = None
  for histogram in tree.getElementsByTagName('histogram'):
    name = histogram.getAttribute('name')
    if last_name is not None and name.lower() < last_name.lower():
      logging.error('Histograms %s and %s are not in alphabetical order',
                    last_name, name)
      have_errors = True
    last_name = name
    if name in histograms:
      logging.error('Duplicate histogram definition %s', name)
      have_errors = True
      continue
    histograms[name] = histogram_entry = {}

    # Find <owner> tag.
    owners = _ExtractOwners(histogram)
    if owners:
      histogram_entry['owners'] = owners

    # Find <summary> tag.
    summary_nodes = histogram.getElementsByTagName('summary')
    if summary_nodes:
      histogram_entry['summary'] = _NormalizeString(
          _JoinChildNodes(summary_nodes[0]))
    else:
      histogram_entry['summary'] = 'TBD'

    # Find <obsolete> tag.
    obsolete_nodes = histogram.getElementsByTagName('obsolete')
    if obsolete_nodes:
      reason = _JoinChildNodes(obsolete_nodes[0])
      histogram_entry['obsolete'] = reason

    # Handle units.
    if histogram.hasAttribute('units'):
      histogram_entry['units'] = histogram.getAttribute('units')

    # Find <details> tag.
    details_nodes = histogram.getElementsByTagName('details')
    if details_nodes:
      histogram_entry['details'] = _NormalizeString(
          _JoinChildNodes(details_nodes[0]))

    # Handle enum types.
    if histogram.hasAttribute('enum'):
      enum_name = histogram.getAttribute('enum')
      if enum_name not in enums:
        logging.error('Unknown enum %s in histogram %s', enum_name, name)
        have_errors = True
      else:
        histogram_entry['enum'] = enums[enum_name]

  return histograms, have_errors


# Finds an <obsolete> node amongst |node|'s immediate children and returns its
# content as a string. Returns None if no such node exists.
def _GetObsoleteReason(node):
  for child in node.childNodes:
    if child.localName == 'obsolete':
      # There can be at most 1 obsolete element per node.
      return _JoinChildNodes(child)
  return None


def _UpdateHistogramsWithSuffixes(tree, histograms):
  """Process <histogram_suffixes> tags and combine with affected histograms.

  The histograms dictionary will be updated in-place by adding new histograms
  created by combining histograms themselves with histogram_suffixes targeting
  these histograms.

  Args:
    tree: XML dom tree.
    histograms: a dictionary of histograms previously extracted from the tree;

  Returns:
    True if any errors were found.
  """
  have_errors = False

  histogram_suffix_tag = 'histogram_suffixes'
  suffix_tag = 'suffix'
  with_tag = 'with-suffix'

  # Verify order of histogram_suffixes fields first.
  last_name = None
  for histogram_suffixes in tree.getElementsByTagName(histogram_suffix_tag):
    name = histogram_suffixes.getAttribute('name')
    if last_name is not None and name.lower() < last_name.lower():
      logging.error('histogram_suffixes %s and %s are not in alphabetical '
                    'order', last_name, name)
      have_errors = True
    last_name = name

  # histogram_suffixes can depend on other histogram_suffixes, so we need to be
  # careful. Make a temporary copy of the list of histogram_suffixes to use as a
  # queue. histogram_suffixes whose dependencies have not yet been processed
  # will get relegated to the back of the queue to be processed later.
  reprocess_queue = []
  def GenerateHistogramSuffixes():
    for f in tree.getElementsByTagName(histogram_suffix_tag):
      yield 0, f
    for r, f in reprocess_queue:
      yield r, f

  for reprocess_count, histogram_suffixes in GenerateHistogramSuffixes():
    # Check dependencies first
    dependencies_valid = True
    affected_histograms = histogram_suffixes.getElementsByTagName(
        'affected-histogram')
    for affected_histogram in affected_histograms:
      histogram_name = affected_histogram.getAttribute('name')
      if histogram_name not in histograms:
        # Base histogram is missing
        dependencies_valid = False
        missing_dependency = histogram_name
        break
    if not dependencies_valid:
      if reprocess_count < MAX_HISTOGRAM_SUFFIX_DEPENDENCY_DEPTH:
        reprocess_queue.append((reprocess_count + 1, histogram_suffixes))
        continue
      else:
        logging.error('histogram_suffixes %s is missing its dependency %s',
                      histogram_suffixes.getAttribute('name'),
                      missing_dependency)
        have_errors = True
        continue

    # If the suffix group has an obsolete tag, all suffixes it generates inherit
    # its reason.
    group_obsolete_reason = _GetObsoleteReason(histogram_suffixes)

    name = histogram_suffixes.getAttribute('name')
    suffix_nodes = histogram_suffixes.getElementsByTagName(suffix_tag)
    suffix_labels = {}
    for suffix in suffix_nodes:
      suffix_labels[suffix.getAttribute('name')] = suffix.getAttribute('label')
    # Find owners list under current histogram_suffixes tag.
    owners = _ExtractOwners(histogram_suffixes)

    last_histogram_name = None
    for affected_histogram in affected_histograms:
      histogram_name = affected_histogram.getAttribute('name')
      if (last_histogram_name is not None
          and histogram_name.lower() < last_histogram_name.lower()):
        logging.error('Affected histograms %s and %s of histogram_suffixes %s '
                      'are not in alphabetical order',
                      last_histogram_name, histogram_name, name)
        have_errors = True
      last_histogram_name = histogram_name
      with_suffixes = affected_histogram.getElementsByTagName(with_tag)
      if with_suffixes:
        suffixes_to_add = with_suffixes
      else:
        suffixes_to_add = suffix_nodes
      for suffix in suffixes_to_add:
        suffix_name = suffix.getAttribute('name')
        try:
          new_histogram_name = _ExpandHistogramNameWithSuffixes(
              suffix_name, histogram_name, histogram_suffixes)
          if new_histogram_name != histogram_name:
            histograms[new_histogram_name] = copy.deepcopy(
                histograms[histogram_name])

          suffix_label = suffix_labels.get(suffix_name, '')

          # TODO(yiyaoliu): Rename these to be consistent with the new naming.
          # It is kept unchanged for now to be it's used by dashboards.
          if 'fieldtrial_groups' not in histograms[new_histogram_name]:
            histograms[new_histogram_name]['fieldtrial_groups'] = []
          histograms[new_histogram_name]['fieldtrial_groups'].append(
              suffix_name)

          if 'fieldtrial_names' not in histograms[new_histogram_name]:
            histograms[new_histogram_name]['fieldtrial_names'] = []
          histograms[new_histogram_name]['fieldtrial_names'].append(name)

          if 'fieldtrial_labels' not in histograms[new_histogram_name]:
            histograms[new_histogram_name]['fieldtrial_labels'] = []
          histograms[new_histogram_name]['fieldtrial_labels'].append(
              suffix_label)

          # If no owners are added for this histogram-suffixes, it inherits the
          # owners of its parents.
          if owners:
            histograms[new_histogram_name]['owners'] = owners

          # If a suffix has an obsolete node, it's marked as obsolete for the
          # specified reason, overwriting its group's obsoletion reason if the
          # group itself was obsolete as well.
          obsolete_reason = _GetObsoleteReason(suffix)
          if not obsolete_reason:
            obsolete_reason = group_obsolete_reason

          # If the suffix has an obsolete tag, all histograms it generates
          # inherit it.
          if obsolete_reason:
            histograms[new_histogram_name]['obsolete'] = obsolete_reason

        except Error:
          have_errors = True

  return have_errors


def ExtractHistogramsFromFile(file_handle):
  """Compute the histogram names and descriptions from the XML representation.

  Args:
    file_handle: A file or file-like with XML content.

  Returns:
    a tuple of (histograms, status) where histograms is a dictionary mapping
    histogram names to dictionaries containing histogram descriptions and status
    is a boolean indicating if errros were encoutered in processing.
  """
  tree = xml.dom.minidom.parse(file_handle)
  _NormalizeAllAttributeValues(tree)

  enums, enum_errors = _ExtractEnumsFromXmlTree(tree)
  histograms, histogram_errors = _ExtractHistogramsFromXmlTree(tree, enums)
  update_errors = _UpdateHistogramsWithSuffixes(tree, histograms)

  return histograms, enum_errors or histogram_errors or update_errors


def ExtractHistograms(filename):
  """Load histogram definitions from a disk file.

  Args:
    filename: a file path to load data from.

  Returns:
    a dictionary of histogram descriptions.

  Raises:
    Error: if the file is not well-formatted.
  """
  with open(filename, 'r') as f:
    histograms, had_errors = ExtractHistogramsFromFile(f)
    if had_errors:
      logging.error('Error parsing %s', filename)
      raise Error()
    return histograms


def ExtractNames(histograms):
  return sorted(histograms.keys())

# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Updates enums in histograms.xml file with values read from provided C++ enum.

If the file was pretty-printed, the updated version is pretty-printed too.
"""

import logging
import os
import re
import sys

from xml.dom import minidom

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'common'))
import diff_util
import path_util

import print_style


HISTOGRAMS_PATH = path_util.GetHistogramsFile()


class UserError(Exception):
  def __init__(self, message):
    Exception.__init__(self, message)

  @property
  def message(self):
    return self.args[0]


def Log(message):
  logging.info(message)


def ReadHistogramValues(filename, start_marker, end_marker):
  """Returns a dictionary of enum values, read from a C++ file.

  Args:
      filename: The unix-style path (relative to src/) of the file to open.
      start_marker: A regex that signifies the start of the enum values.
      end_marker: A regex that signifies the end of the enum values.
  """
  # Read the file as a list of lines
  with open(path_util.GetInputFile(filename)) as f:
    content = f.readlines()

  START_REGEX = re.compile(start_marker)
  ITEM_REGEX = re.compile(r'^(\w+)')
  ITEM_REGEX_WITH_INIT = re.compile(r'(\w+)\s*=\s*(\d+)')
  END_REGEX = re.compile(end_marker)

  # Locate the enum definition and collect all entries in it
  inside_enum = False # We haven't found the enum definition yet
  result = {}
  for line in content:
    line = line.strip()
    if inside_enum:
      # Exit condition: we reached last enum value
      if END_REGEX.match(line):
        inside_enum = False
      else:
        # Inside enum: generate new xml entry
        m = ITEM_REGEX_WITH_INIT.match(line)
        if m:
          enum_value = int(m.group(2))
          label = m.group(1)
        else:
          m = ITEM_REGEX.match(line)
          if m:
            label = m.group(1)
          else:
            continue
        result[enum_value] = label
        enum_value += 1
    else:
      if START_REGEX.match(line):
        inside_enum = True
        enum_value = 0
  return result


def CreateEnumItemNode(document, value, label):
  """Creates an int element to append to an enum."""
  item_node = document.createElement('int')
  item_node.attributes['value'] = str(value)
  item_node.attributes['label'] = label
  return item_node


def UpdateHistogramDefinitions(histogram_enum_name, source_enum_values,
                               source_enum_path, document):
  """Updates the enum node named |histogram_enum_name| based on the definition
  stored in |source_enum_values|. Existing items for which |source_enum_values|
  doesn't contain any corresponding data will be preserved. |source_enum_path|
  will be used to insert a comment.
  """
  # Get a dom of <enum name=|histogram_enum_name| ...> node in |document|.
  for enum_node in document.getElementsByTagName('enum'):
    if enum_node.attributes['name'].value == histogram_enum_name:
      break
  else:
    raise UserError('No {0} enum node found'.format(histogram_enum_name))

  new_item_nodes = {}
  new_comments = []

  # Add a "Generated from (...)" comment.
  new_comments.append(
      document.createComment(' Generated from {0} '.format(source_enum_path)))

  # Create item nodes for each of the enum values.
  for value, label in source_enum_values.iteritems():
    new_item_nodes[value] = CreateEnumItemNode(document, value, label)

  # Scan existing nodes in |enum_node| for old values and preserve them.
  # - Preserve comments other than the 'Generated from' comment. NOTE:
  #   this does not preserve the order of the comments in relation to the
  #   old values.
  # - Drop anything else.
  SOURCE_COMMENT_REGEX = re.compile('^ Generated from ')
  for child in enum_node.childNodes:
    if child.nodeName == 'int':
      value = int(child.attributes['value'].value)
      if not source_enum_values.has_key(value):
        new_item_nodes[value] = child
    # Preserve existing non-generated comments.
    elif (child.nodeType == minidom.Node.COMMENT_NODE and
          SOURCE_COMMENT_REGEX.match(child.data) is None):
      new_comments.append(child)

  # Update |enum_node|. First, remove everything existing.
  while enum_node.hasChildNodes():
    enum_node.removeChild(enum_node.lastChild)

  # Add comments at the top.
  for comment in new_comments:
    enum_node.appendChild(comment)

  # Add in the new enums.
  for value in sorted(new_item_nodes.iterkeys()):
    enum_node.appendChild(new_item_nodes[value])


def _GetOldAndUpdatedXml(histogram_enum_name, source_enum_values,
                         source_enum_path):
  """Reads old histogram from |histogram_enum_name| from |HISTOGRAMS_PATH|, and
  calculates new histogram from |source_enum_values| from |source_enum_path|,
  and returns both in XML format.
  """
  Log('Reading existing histograms from "{0}".'.format(HISTOGRAMS_PATH))
  with open(HISTOGRAMS_PATH, 'rb') as f:
    histograms_doc = minidom.parse(f)
    f.seek(0)
    xml = f.read()

  Log('Comparing histograms enum with new enum definition.')
  UpdateHistogramDefinitions(histogram_enum_name, source_enum_values,
                             source_enum_path, histograms_doc)

  new_xml = print_style.GetPrintStyle().PrettyPrintNode(histograms_doc)
  return (xml, new_xml)


def HistogramNeedsUpdate(histogram_enum_name, source_enum_path, start_marker,
                         end_marker):
  """Reads a C++ enum from a .h file and does a dry run of updating
  histograms.xml to match. Returns true if the histograms.xml file would be
  changed.

  Args:
      histogram_enum_name: The name of the XML <enum> attribute to update.
      source_enum_path: A unix-style path, relative to src/, giving
          the C++ header file from which to read the enum.
      start_marker: A regular expression that matches the start of the C++ enum.
      end_marker: A regular expression that matches the end of the C++ enum.
  """
  Log('Reading histogram enum definition from "{0}".'.format(source_enum_path))
  source_enum_values = ReadHistogramValues(source_enum_path, start_marker,
                                           end_marker)

  (xml, new_xml) = _GetOldAndUpdatedXml(histogram_enum_name, source_enum_values,
                                        source_enum_path)
  return xml != new_xml


def UpdateHistogramFromDict(histogram_enum_name, source_enum_values,
                            source_enum_path):
  """Updates |histogram_enum_name| enum in histograms.xml file with values
  from the {value: 'key'} dictionary |source_enum_values|. A comment is added
  to histograms.xml citing that the values in |histogram_enum_name| were
  sourced from |source_enum_path|.
  """
  (xml, new_xml) = _GetOldAndUpdatedXml(histogram_enum_name, source_enum_values,
                                        source_enum_path)
  if not diff_util.PromptUserToAcceptDiff(
      xml, new_xml, 'Is the updated version acceptable?'):
    Log('Cancelled.')
    return

  with open(HISTOGRAMS_PATH, 'wb') as f:
    f.write(new_xml)

  Log('Done.')


def UpdateHistogramEnum(histogram_enum_name, source_enum_path,
                        start_marker, end_marker):
  """Reads a C++ enum from a .h file and updates histograms.xml to match.

  Args:
      histogram_enum_name: The name of the XML <enum> attribute to update.
      source_enum_path: A unix-style path, relative to src/, giving
          the C++ header file from which to read the enum.
      start_marker: A regular expression that matches the start of the C++ enum.
      end_marker: A regular expression that matches the end of the C++ enum.
  """

  Log('Reading histogram enum definition from "{0}".'.format(source_enum_path))
  source_enum_values = ReadHistogramValues(source_enum_path, start_marker,
                                           end_marker)

  UpdateHistogramFromDict(histogram_enum_name, source_enum_values,
      source_enum_path)

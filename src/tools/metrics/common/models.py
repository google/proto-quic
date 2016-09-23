# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Model types for describing description xml models."""

from xml.dom import minidom

import sys
import os

import pretty_print_xml


def GetComments(node):
  """Extracts comments in the current node.

  Args:
    node: The DOM node to extract comments from.
  Returns:
    A list of comment DOM nodes.
  """
  return [n for n in node.childNodes if n.nodeType == minidom.Node.COMMENT_NODE]


def PutComments(node, comments):
  """Append comments to the DOM node.

  Args:
    node: The DOM node to write comments to.
    comments: A list of comment DOM nodes.
  """
  for n in comments:
    node.appendChild(n)


class NodeType(object):
  """Base type for a type of XML node.

  Args:
    dont_indent: True iff this node should not have it's children indented
        when pretty printing.
    extra_newlines: None or a triple of integers describing the number of
        newlines that should be printed (after_open, before_close, after_close)
    single_line: True iff this node may be squashed into a single line.
  """

  def __init__(self, tag,
               dont_indent=False,
               extra_newlines=None,
               single_line=False):
    self.tag = tag
    self.dont_indent = dont_indent
    self.extra_newlines = extra_newlines
    self.single_line = single_line

  def Unmarshall(self, unused_node):
    return None

  def Marshall(self, unused_doc, unused_obj):
    return None

  def GetAttributes(self):
    return []

  def GetNodeTypes(self):
    return {self.tag: self}


class TextNodeType(NodeType):
  """A type for simple nodes that just have a tag and some text content.

  Unmarshalls nodes to strings.

  Args:
    tag: The name of XML tag for this type of node.
  """

  def __init__(self, tag, **kwargs):
    NodeType.__init__(self, tag, **kwargs)

  def __str__(self):
    return 'TextNodeType("%s")' % self.tag

  def Unmarshall(self, node):
    return node.firstChild.nodeValue.strip()

  def Marshall(self, doc, obj):
    node = doc.createElement(self.tag)
    node.appendChild(doc.createTextNode(obj))
    return node


class ChildType(object):
  """Metadata about a nodes children.

  Args:
    attr: The field name of the parents model object storing the child's model.
    node_type: The NodeType of the child.
    multiple: True if the child can be repeated.
  """

  def __init__(self, attr, node_type, multiple):
    self.attr = attr
    self.node_type = node_type
    self.multiple = multiple


class ObjectNodeType(NodeType):
  """A complex node type that has attributes or other nodes as children.

  Unmarshalls nodes to objects.

  Args:
    tag: The name of XML tag for this type of node.
    int_attributes: A list of names of integer attributes.
    float_attributes: A list of names of float attributes.
    string_attributes: A list of names of string attributes.
    children: A list of ChildTypes describing the objects children.
  """

  def __init__(self, tag,
               int_attributes=None,
               float_attributes=None,
               string_attributes=None,
               children=None,
               **kwargs):
    NodeType.__init__(self, tag, **kwargs)
    self.int_attributes = int_attributes or []
    self.float_attributes = float_attributes or []
    self.string_attributes = string_attributes or []
    self.children = children or []

  def __str__(self):
    return 'ObjectNodeType("%s")' % self.tag

  def Unmarshall(self, node):
    obj = {}

    obj['comments'] = GetComments(node)

    for attr in self.int_attributes:
      obj[attr] = int(node.getAttribute(attr))

    for attr in self.float_attributes:
      obj[attr] = float(node.getAttribute(attr))

    for attr in self.string_attributes:
      obj[attr] = unicode(node.getAttribute(attr))

    for child in self.children:
      nodes = node.getElementsByTagName(child.node_type.tag)
      if child.multiple:
        obj[child.attr] = [child.node_type.Unmarshall(n) for n in nodes]
      else:
        if not nodes:
          raise ValueError("Missing required tag '%s'" % child.node_type.tag)
        obj[child.attr] = child.node_type.Unmarshall(nodes[0])
    return obj

  def Marshall(self, doc, obj):
    node = doc.createElement(self.tag)
    attributes = (self.int_attributes +
                  self.float_attributes +
                  self.string_attributes)
    for attr in attributes:
      value = str(obj[attr])
      if value:
        node.setAttribute(attr, value)

    PutComments(node, obj['comments'])

    for child in self.children:
      if child.multiple:
        for o in obj[child.attr]:
          node.appendChild(child.node_type.Marshall(doc, o))
      else:
        node.appendChild(child.node_type.Marshall(doc, obj[child.attr]))
    return node

  def GetAttributes(self):
    return self.int_attributes + self.float_attributes + self.string_attributes

  def GetNodeTypes(self):
    types = {self.tag: self}
    for child in self.children:
      types.update(child.node_type.GetNodeTypes())
    return types


class DocumentType(object):
  """Model for the root of an XML description file.

  Args:
    root_type: A NodeType describing the root tag of the document.
  """

  def __init__(self, root_type):
    self.root_type = root_type

  def Parse(self, input_file):
    tree = minidom.parseString(input_file)
    comments = GetComments(tree)
    return comments, self.root_type.Unmarshall(
        tree.getElementsByTagName(self.root_type.tag)[0])

  def GetPrintStyle(self):
    types = self.root_type.GetNodeTypes()
    return pretty_print_xml.XmlStyle(
        {t: types[t].GetAttributes() for t in types},
        {t: types[t].extra_newlines for t in types if types[t].extra_newlines},
        [t for t in types if types[t].dont_indent],
        [t for t in types if types[t].single_line],
        {})

  def ToXML(self, comments, obj):
    doc = minidom.Document()
    for comment in comments:
      doc.appendChild(comment)
    doc.appendChild(self.root_type.Marshall(doc, obj))
    return doc

  def PrettyPrint(self, comments, obj):
    return self.GetPrintStyle().PrettyPrintNode(self.ToXML(comments, obj))

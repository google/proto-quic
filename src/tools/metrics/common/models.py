# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Types for building models of metric description xml files.

UMA uses several XML files to allow clients to describe the metrics that they
collect, e.g.
https://chromium.googlesource.com/chromium/src/+/master/tools/metrics/rappor/rappor.xml

These types can be used to build models that describe the canonical formatted
structure of these files, and the models can be used to extract the contents of
those files, or convert content back into a canonicalized version of the file.
"""

import abc
from xml.dom import minidom

import pretty_print_xml


# A non-basic type key for storing comments, so they don't conflict with
# regular keys, and can be skipped in JSON serialization.
COMMENT_KEY = ('comment',)


def GetComments(node):
  """Extracts comments in the current node.

  Args:
    node: The DOM node to extract comments from.

  Returns:
    A list of comment DOM nodes.
  """
  return [node for node in node.childNodes
          if node.nodeType == minidom.Node.COMMENT_NODE]


def PutComments(node, comments):
  """Appends comments to the DOM node.

  Args:
    node: The DOM node to write comments to.
    comments: A list of comment DOM nodes.
  """
  for comment in comments:
    node.appendChild(comment)


class NodeType(object):
  """Base type for a type of XML node.

  Args:
    indent: True iff this node should have its children indented when pretty
        printing.
    extra_newlines: None or a triple of integers describing the number of
        newlines that should be printed (after_open, before_close, after_close)
    single_line: True iff this node may be squashed into a single line.
  """
  __metaclass__ = abc.ABCMeta

  def __init__(self, tag,
               indent=True,
               extra_newlines=None,
               single_line=False):
    self.tag = tag
    self.indent = indent
    self.extra_newlines = extra_newlines
    self.single_line = single_line

  @abc.abstractmethod
  def Unmarshall(self, node):
    """Extracts the content of the node to an object.

    Args:
      node: The XML node to extract data from.

    Returns:
      An object extracted from the node.
    """

  @abc.abstractmethod
  def Marshall(self, doc, obj):
    """Converts an object into an XML node of this type.

    Args:
      doc: A document create an XML node in.
      obj: The object to be encoded into the XML.

    Returns:
      An XML node encoding the object.
    """

  def GetAttributes(self):
    """Gets a sorted list of attributes that this node can have.

    Returns:
      A list of names of XML attributes, sorted by the order they should appear.
    """
    return []

  def GetNodeTypes(self):
    """Gets a map of tags to node types for all dependent types.

    Returns:
      A map of tags to node-types for this node and all of the nodes that it
      can contain.
    """
    return {self.tag: self}


class TextNodeType(NodeType):
  """A type for simple nodes that just have a tag and some text content.

  Unmarshalls nodes to strings.

  Args:
    tag: The name of XML tag for this type of node.
  """

  def __str__(self):
    return 'TextNodeType("%s")' % self.tag

  def Unmarshall(self, node):
    """Extracts the content of the node to an object.

    Args:
      node: The XML node to extract data from.

    Returns:
      The string content of the node.
    """
    if not node.firstChild:
      return ''
    text = node.firstChild.nodeValue
    return '\n\n'.join(pretty_print_xml.SplitParagraphs(text))

  def Marshall(self, doc, obj):
    """Converts an object into an XML node of this type.

    Args:
      doc: A document create an XML node in.
      obj: A string to be encoded into the XML.

    Returns:
      An XML node encoding the object.
    """
    node = doc.createElement(self.tag)
    if obj:
      node.appendChild(doc.createTextNode(obj))
    return node


class ChildType(object):
  """Metadata about a node type's children.

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
    attributes: A list of (name, type) pairs, e.g. [('foo', unicode)].  The
        order of the attributes determines the ordering of attributes, when
        serializing objects to XML.
    text_attribute: An attribute stored in the text content of the node.
    children: A list of ChildTypes describing the objects children.

  Raises:
    ValueError: Attributes contains duplicate definitions.
  """

  def __init__(self, tag,
               attributes=None,
               children=None,
               text_attribute=None,
               **kwargs):
    NodeType.__init__(self, tag, **kwargs)
    self.attributes = attributes or []
    self.children = children or []
    self.text_attribute = text_attribute
    if len(self.attributes) != len(dict(self.attributes)):
      raise ValueError('Duplicate attribute definition.')

  def __str__(self):
    return 'ObjectNodeType("%s")' % self.tag

  def Unmarshall(self, node):
    """Extracts the content of the node to an object.

    Args:
      node: The XML node to extract data from.

    Returns:
      An object extracted from the node.

    Raises:
      ValueError: The node is missing required children.
    """
    obj = {}

    obj[COMMENT_KEY] = GetComments(node)

    for attr, attr_type in self.attributes:
      if node.hasAttribute(attr):
        obj[attr] = attr_type(node.getAttribute(attr))

    if self.text_attribute and node.firstChild:
      obj[self.text_attribute] = node.firstChild.nodeValue.strip()

    for child in self.children:
      nodes = node.getElementsByTagName(child.node_type.tag)
      if child.multiple:
        obj[child.attr] = [child.node_type.Unmarshall(n) for n in nodes]
      elif nodes:
        obj[child.attr] = child.node_type.Unmarshall(nodes[0])
    return obj

  def Marshall(self, doc, obj):
    """Converts an object into an XML node of this type.

    Args:
      doc: A document create an XML node in.
      obj: The object to be encoded into the XML.

    Returns:
      An XML node encoding the object.
    """
    node = doc.createElement(self.tag)
    for attr, _ in self.attributes:
      if attr in obj:
        node.setAttribute(attr, str(obj[attr]))

    PutComments(node, obj[COMMENT_KEY])

    if self.text_attribute and self.text_attribute in obj:
      node.appendChild(doc.createTextNode(obj[self.text_attribute]))

    for child in self.children:
      if child.multiple:
        for child_obj in obj[child.attr]:
          node.appendChild(child.node_type.Marshall(doc, child_obj))
      elif child.attr in obj:
        node.appendChild(child.node_type.Marshall(doc, obj[child.attr]))
    return node

  def GetAttributes(self):
    """Gets a sorted list of attributes that this node can have.

    Returns:
      A list of names of XML attributes, sorted by the order they should appear.
    """
    return [attr for attr, _ in self.attributes]

  def GetNodeTypes(self):
    """Get a map of tags to node types for all dependent types.

    Returns:
      A map of tags to node-types for this node and all of the nodes that it
      can contain.
    """
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
    """Parses the data out of an XML file's contents.

    Args:
      input_file: The content of an XML file, as a string.

    Returns:
      A list of the file level comment nodes, an object representing the
      unmarshalled content of the document's root node.
    """
    tree = minidom.parseString(input_file)
    comments = GetComments(tree)
    return comments, self.root_type.Unmarshall(
        tree.getElementsByTagName(self.root_type.tag)[0])

  def GetPrintStyle(self):
    """Gets an XmlStyle object for pretty printing a document of this type.

    Returns:
      An XML style object.
    """
    types = self.root_type.GetNodeTypes()
    return pretty_print_xml.XmlStyle(
        attribute_order={t: types[t].GetAttributes() for t in types},
        tags_that_have_extra_newline={t: types[t].extra_newlines for t in types
                                      if types[t].extra_newlines},
        tags_that_dont_indent=[t for t in types if not types[t].indent],
        tags_that_allow_single_line=[t for t in types if types[t].single_line],
        tags_alphabetization_rules={})

  def ToXML(self, comments, obj):
    """Converts an object into an XML document.

    Args:
      comments: A list of file level comment nodes to include.
      obj: An object to serialize to XML.

    Returns:
      An XML minidom Document object.
    """
    doc = minidom.Document()
    for comment in comments:
      doc.appendChild(comment)
    doc.appendChild(self.root_type.Marshall(doc, obj))
    return doc

  def PrettyPrint(self, comments, obj):
    """Converts an object into pretty-printed XML as a string.

    Args:
      comments: A list of file level comment nodes to include.
      obj: An object to serialize to XML.

    Returns:
      A string containing pretty printed XML.
    """
    return self.GetPrintStyle().PrettyPrintNode(self.ToXML(comments, obj))

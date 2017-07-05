#!/usr/bin/env python
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Parser for Web IDL."""

#
# IDL Parser
#
# The parser is uses the PLY yacc library to build a set of parsing rules based
# on Web IDL.
#
# Web IDL, and Web IDL grammar can be found at:
#   http://heycam.github.io/webidl/
# PLY can be found at:
#   http://www.dabeaz.com/ply/
#
# The parser generates a tree by recursively matching sets of items against
# defined patterns.  When a match is made, that set of items is reduced
# to a new item.   The new item can provide a match for parent patterns.
# In this way an AST is built (reduced) depth first.
#

#
# Disable check for line length and Member as Function due to how grammar rules
# are defined with PLY
#
# pylint: disable=R0201
# pylint: disable=C0301

import os.path
import sys
import time

from idl_lexer import IDLLexer
from idl_node import IDLAttribute
from idl_node import IDLNode

SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
sys.path.insert(0, os.path.join(SRC_DIR, 'third_party'))
from ply import lex
from ply import yacc


#
# ERROR_REMAP
#
# Maps the standard error formula into a more friendly error message.
#
ERROR_REMAP = {
  'Unexpected ")" after "(".' : 'Empty argument list.',
  'Unexpected ")" after ",".' : 'Missing argument.',
  'Unexpected "}" after ",".' : 'Trailing comma in block.',
  'Unexpected "}" after "{".' : 'Unexpected empty block.',
  'Unexpected "{" after keyword "enum".' : 'Enum missing name.',
  'Unexpected "{" after keyword "struct".' : 'Struct missing name.',
  'Unexpected "{" after keyword "interface".' : 'Interface missing name.',
}


def Boolean(val):
  """Convert to strict boolean type."""
  if val:
    return True
  return False


def ListFromConcat(*items):
  """Generate list by concatenating inputs"""
  itemsout = []
  for item in items:
    if item is None:
      continue
    if type(item) is not type([]):
      itemsout.append(item)
    else:
      itemsout.extend(item)

  return itemsout

def ExpandProduction(p):
  if type(p) == list:
    return '[' + ', '.join([ExpandProduction(x) for x in p]) + ']'
  if type(p) == IDLNode:
    return 'Node:' + str(p)
  if type(p) == IDLAttribute:
    return 'Attr:' + str(p)
  if type(p) == str:
    return 'str:' + p
  return '%s:%s' % (p.__class__.__name__, str(p))

# TokenTypeName
#
# Generate a string which has the type and value of the token.
#
def TokenTypeName(t):
  if t.type == 'SYMBOL':
    return 'symbol %s' % t.value
  if t.type in ['HEX', 'INT', 'OCT', 'FLOAT']:
    return 'value %s' % t.value
  if t.type == 'string' :
    return 'string "%s"' % t.value
  if t.type == t.value:
    return '"%s"' % t.value
  if t.type == ',':
    return 'Comma'
  if t.type == 'identifier':
    return 'identifier "%s"' % t.value
  return 'keyword "%s"' % t.value


#
# IDL Parser
#
# The Parser inherits the from the Lexer to provide PLY with the tokenizing
# definitions.  Parsing patterns are encoded as functions where p_<name> is
# is called any time a patern matching the function documentation is found.
# Paterns are expressed in the form of:
# """ <new item> : <item> ....
#                | <item> ...."""
#
# Where new item is the result of a match against one or more sets of items
# separated by the "|".
#
# The function is called with an object 'p' where p[0] is the output object
# and p[n] is the set of inputs for positive values of 'n'.  Len(p) can be
# used to distinguish between multiple item sets in the pattern.
#
# The rules can look cryptic at first, but there are a few standard
# transforms from the CST to AST. With these in mind, the actions should
# be reasonably legible.
#
# * Ignore production
#   Discard this branch. Primarily used when one alternative is empty.
#
#   Sample code:
#   if len(p) > 1:
#       p[0] = ...
#   # Note no assignment if len(p) == 1
#
# * Eliminate singleton production
#   Discard this node in the CST, pass the next level down up the tree.
#   Used to ignore productions only necessary for parsing, but not needed
#   in the AST.
#
#   Sample code:
#   p[0] = p[1]
#
# * Build node
#   The key type of rule. In this parser, produces object of class IDLNode.
#   There are several helper functions:
#   * BuildProduction: actually builds an IDLNode, based on a production.
#   * BuildAttribute: builds an IDLAttribute, which is a temporary
#                     object to hold a name-value pair, which is then
#                     set as a Property of the IDLNode when the IDLNode
#                     is built.
#   * BuildNamed: Same as BuildProduction, and sets the 'NAME' property.
#   * BuildTrue: BuildAttribute with value True, for flags.
#
#   Sample code:
#   # Build node of type NodeType, with value p[1], and children.
#   p[0] = self.BuildProduction('NodeType', p, 1, children)
#
#   # Build named node of type NodeType, with name and value p[1].
#   # (children optional)
#   p[0] = self.BuildNamed('NodeType', p, 1)
#
#   # Make a list
#   # Used if one node has several children.
#   children = ListFromConcat(p[2], p[3])
#   p[0] = self.BuildProduction('NodeType', p, 1, children)
#
#   # Also used to collapse the right-associative tree
#   # produced by parsing a list back into a single list.
#   """Foos : Foo Foos
#           |"""
#   if len(p) > 1:
#       p[0] = ListFromConcat(p[1], p[2])
#
#   # Add children.
#   # Primarily used to add attributes, produced via BuildTrue.
#   # p_StaticAttribute
#   """StaticAttribute : STATIC Attribute"""
#   p[2].AddChildren(self.BuildTrue('STATIC'))
#   p[0] = p[2]
#
# For more details on parsing refer to the PLY documentation at
#    http://www.dabeaz.com/ply/
#
# The parser is based on the Web IDL standard.  See:
#    http://heycam.github.io/webidl/#idl-grammar
#
# Productions with a fractional component in the comment denote additions to
# the Web IDL spec, such as allowing string list in extended attributes.
class IDLParser(object):
  def p_Definitions(self, p):
    """Definitions : ExtendedAttributeList Definition Definitions
           | """
    if len(p) > 1:
      p[2].AddChildren(p[1])
      p[0] = ListFromConcat(p[2], p[3])

  def p_Definition(self, p):
    """Definition : CallbackOrInterface
                  | Partial
                  | Dictionary
                  | Enum
                  | Typedef
                  | ImplementsStatement"""
    p[0] = p[1]

  # Error recovery for definition
  def p_DefinitionError(self, p):
    """Definition : error ';'"""
    p[0] = self.BuildError(p, 'Definition')

  def p_CallbackOrInterface(self, p):
    """CallbackOrInterface : CALLBACK CallbackRestOrInterface
                           | Interface"""
    if len(p) > 2:
      p[2].AddChildren(self.BuildTrue('CALLBACK'))
      p[0] = p[2]
    else:
      p[0] = p[1]

  def p_CallbackRestOrInterface(self, p):
    """CallbackRestOrInterface : CallbackRest
                               | Interface"""
    p[0] = p[1]

  def p_Interface(self, p):
    """Interface : INTERFACE identifier Inheritance '{' InterfaceMembers '}' ';'"""
    p[0] = self.BuildNamed('Interface', p, 2, ListFromConcat(p[3], p[5]))

  # Error recovery for interface.
  def p_InterfaceError(self, p):
    """Interface : INTERFACE identifier Inheritance '{' error"""
    p[0] = self.BuildError(p, 'Interface')

  def p_Partial(self, p):
    """Partial : PARTIAL PartialDefinition"""
    p[2].AddChildren(self.BuildTrue('Partial'))
    p[0] = p[2]

  # Error recovery for Partial
  def p_PartialError(self, p):
    """Partial : PARTIAL error"""
    p[0] = self.BuildError(p, 'Partial')

  def p_PartialDefinition(self, p):
    """PartialDefinition : PartialDictionary
                         | PartialInterface"""
    p[0] = p[1]

  def p_PartialInterface(self, p):
    """PartialInterface : INTERFACE identifier '{' InterfaceMembers '}' ';'"""
    p[0] = self.BuildNamed('Interface', p, 2, p[4])

  def p_InterfaceMembers(self, p):
    """InterfaceMembers : ExtendedAttributeList InterfaceMember InterfaceMembers
                        |"""
    if len(p) > 1:
      p[2].AddChildren(p[1])
      p[0] = ListFromConcat(p[2], p[3])

  # Error recovery for InterfaceMembers
  def p_InterfaceMembersError(self, p):
    """InterfaceMembers : error"""
    p[0] = self.BuildError(p, 'InterfaceMembers')

  # Removed unsupported: Serializer
  def p_InterfaceMember(self, p):
    """InterfaceMember : Const
                       | Operation
                       | Serializer
                       | Stringifier
                       | StaticMember
                       | Iterable
                       | ReadonlyMember
                       | ReadWriteAttribute
                       | ReadWriteMaplike
                       | ReadWriteSetlike"""
    p[0] = p[1]

  def p_Dictionary(self, p):
    """Dictionary : DICTIONARY identifier Inheritance '{' DictionaryMembers '}' ';'"""
    p[0] = self.BuildNamed('Dictionary', p, 2, ListFromConcat(p[3], p[5]))

  # Error recovery for regular Dictionary
  def p_DictionaryError(self, p):
    """Dictionary : DICTIONARY error ';'"""
    p[0] = self.BuildError(p, 'Dictionary')

  # Error recovery for regular Dictionary
  # (for errors inside dictionary definition)
  def p_DictionaryError2(self, p):
    """Dictionary : DICTIONARY identifier Inheritance '{' error"""
    p[0] = self.BuildError(p, 'Dictionary')

  def p_DictionaryMembers(self, p):
    """DictionaryMembers : ExtendedAttributeList DictionaryMember DictionaryMembers
                         |"""
    if len(p) > 1:
      p[2].AddChildren(p[1])
      p[0] = ListFromConcat(p[2], p[3])

  # Error recovery for DictionaryMembers
  def p_DictionaryMembersError(self, p):
    """DictionaryMembers : ExtendedAttributeList error"""
    p[0] = self.BuildError(p, 'DictionaryMembers')

  def p_DictionaryMember(self, p):
    """DictionaryMember : Required Type identifier Default ';'"""
    p[0] = self.BuildNamed('Key', p, 3, ListFromConcat(p[1], p[2], p[4]))

  def p_Required(self, p):
    """Required : REQUIRED
                |"""
    if len(p) > 1:
      p[0] = self.BuildTrue('REQUIRED')

  def p_PartialDictionary(self, p):
    """PartialDictionary : DICTIONARY identifier '{' DictionaryMembers '}' ';'"""
    partial = self.BuildTrue('Partial')
    p[0] = self.BuildNamed('Dictionary', p, 2, ListFromConcat(p[4], partial))

  # Error recovery for Partial Dictionary
  def p_PartialDictionaryError(self, p):
    """PartialDictionary : DICTIONARY error ';'"""
    p[0] = self.BuildError(p, 'PartialDictionary')

  def p_Default(self, p):
    """Default : '=' DefaultValue
               |"""
    if len(p) > 1:
      p[0] = self.BuildProduction('Default', p, 2, p[2])

  def p_DefaultValue(self, p):
    """DefaultValue : ConstValue
                    | string
                    | '[' ']'"""
    if len(p) == 3:
      p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'sequence'),
                            self.BuildAttribute('VALUE', '[]'))
    elif type(p[1]) == str:
      p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'DOMString'),
                            self.BuildAttribute('NAME', p[1]))
    else:
      p[0] = p[1]

  def p_Inheritance(self, p):
    """Inheritance : ':' identifier
                   |"""
    if len(p) > 1:
      p[0] = self.BuildNamed('Inherit', p, 2)

  def p_Enum(self, p):
    """Enum : ENUM identifier '{' EnumValueList '}' ';'"""
    p[0] = self.BuildNamed('Enum', p, 2, p[4])

  # Error recovery for Enums
  def p_EnumError(self, p):
    """Enum : ENUM error ';'"""
    p[0] = self.BuildError(p, 'Enum')

  def p_EnumValueList(self, p):
    """EnumValueList : ExtendedAttributeList string EnumValueListComma"""
    enum = self.BuildNamed('EnumItem', p, 2, p[1])
    p[0] = ListFromConcat(enum, p[3])

  def p_EnumValueListComma(self, p):
    """EnumValueListComma : ',' EnumValueListString
                          |"""
    if len(p) > 1:
      p[0] = p[2]

  def p_EnumValueListString(self, p):
    """EnumValueListString : ExtendedAttributeList string EnumValueListComma
                           |"""
    if len(p) > 1:
      enum = self.BuildNamed('EnumItem', p, 2, p[1])
      p[0] = ListFromConcat(enum, p[3])

  def p_CallbackRest(self, p):
    """CallbackRest : identifier '=' ReturnType '(' ArgumentList ')' ';'"""
    arguments = self.BuildProduction('Arguments', p, 4, p[5])
    p[0] = self.BuildNamed('Callback', p, 1, ListFromConcat(p[3], arguments))

  def p_Typedef(self, p):
    """Typedef : TYPEDEF ExtendedAttributeList Type identifier ';'"""
    p[0] = self.BuildNamed('Typedef', p, 4, ListFromConcat(p[2], p[3]))

  # Error recovery for Typedefs
  def p_TypedefError(self, p):
    """Typedef : TYPEDEF error ';'"""
    p[0] = self.BuildError(p, 'Typedef')

  def p_ImplementsStatement(self, p):
    """ImplementsStatement : identifier IMPLEMENTS identifier ';'"""
    name = self.BuildAttribute('REFERENCE', p[3])
    p[0] = self.BuildNamed('Implements', p, 1, name)

  def p_Const(self,  p):
    """Const : CONST ConstType identifier '=' ConstValue ';'"""
    value = self.BuildProduction('Value', p, 5, p[5])
    p[0] = self.BuildNamed('Const', p, 3, ListFromConcat(p[2], value))

  def p_ConstValue(self, p):
    """ConstValue : BooleanLiteral
                  | FloatLiteral
                  | integer
                  | null"""
    if type(p[1]) == str:
      p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'integer'),
                            self.BuildAttribute('NAME', p[1]))
    else:
      p[0] = p[1]

  # Add definition for NULL
  def p_null(self, p):
    """null : NULL"""
    p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'NULL'),
                          self.BuildAttribute('NAME', 'NULL'))

  def p_BooleanLiteral(self, p):
    """BooleanLiteral : TRUE
                      | FALSE"""
    value = self.BuildAttribute('VALUE', Boolean(p[1] == 'true'))
    p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'boolean'), value)

  def p_FloatLiteral(self, p):
    """FloatLiteral : float
                    | '-' INFINITY
                    | INFINITY
                    | NAN """
    if len(p) > 2:
      val = '-Infinity'
    else:
      val = p[1]
    p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'float'),
                          self.BuildAttribute('VALUE', val))

  def p_Serializer(self, p):
    """Serializer : SERIALIZER SerializerRest"""
    p[0] = self.BuildProduction('Serializer', p, 1, p[2])

  # TODO(jl): This adds ReturnType and ';', missing from the spec's grammar.
  # https://www.w3.org/Bugs/Public/show_bug.cgi?id=20361
  def p_SerializerRest(self, p):
    """SerializerRest : ReturnType OperationRest
                      | '=' SerializationPattern ';'
                      | ';'"""
    if len(p) == 3:
      p[2].AddChildren(p[1])
      p[0] = p[2]
    elif len(p) == 4:
      p[0] = p[2]

  def p_SerializationPattern(self, p):
    """SerializationPattern : '{' SerializationPatternMap '}'
                            | '[' SerializationPatternList ']'
                            | identifier"""
    if len(p) > 2:
      p[0] = p[2]
    else:
      p[0] = self.BuildAttribute('ATTRIBUTE', p[1])

  # TODO(jl): This adds the "ATTRIBUTE" and "INHERIT ',' ATTRIBUTE" variants,
  # missing from the spec's grammar.
  # https://www.w3.org/Bugs/Public/show_bug.cgi?id=20361
  def p_SerializationPatternMap(self, p):
    """SerializationPatternMap : GETTER
                               | ATTRIBUTE
                               | INHERIT ',' ATTRIBUTE
                               | INHERIT Identifiers
                               | identifier Identifiers
                               |"""
    p[0] = self.BuildProduction('Map', p, 0)
    if len(p) == 4:
      p[0].AddChildren(self.BuildTrue('INHERIT'))
      p[0].AddChildren(self.BuildTrue('ATTRIBUTE'))
    elif len(p) > 1:
      if p[1] == 'getter':
        p[0].AddChildren(self.BuildTrue('GETTER'))
      elif p[1] == 'attribute':
        p[0].AddChildren(self.BuildTrue('ATTRIBUTE'))
      else:
        if p[1] == 'inherit':
          p[0].AddChildren(self.BuildTrue('INHERIT'))
          attributes = p[2]
        else:
          attributes = ListFromConcat(p[1], p[2])
        p[0].AddChildren(self.BuildAttribute('ATTRIBUTES', attributes))

  def p_SerializationPatternList(self, p):
    """SerializationPatternList : GETTER
                                | identifier Identifiers
                                |"""
    p[0] = self.BuildProduction('List', p, 0)
    if len(p) > 1:
      if p[1] == 'getter':
        p[0].AddChildren(self.BuildTrue('GETTER'))
      else:
        attributes = ListFromConcat(p[1], p[2])
        p[0].AddChildren(self.BuildAttribute('ATTRIBUTES', attributes))

  def p_Stringifier(self, p):
    """Stringifier : STRINGIFIER StringifierRest"""
    p[0] = self.BuildProduction('Stringifier', p, 1, p[2])

  def p_StringifierRest(self, p):
    """StringifierRest : ReadOnly AttributeRest
                       | ReturnType OperationRest
                       | ';'"""
    if len(p) == 3:
      p[2].AddChildren(p[1])
      p[0] = p[2]

  def p_StaticMember(self, p):
    """StaticMember : STATIC StaticMemberRest"""
    p[2].AddChildren(self.BuildTrue('STATIC'))
    p[0] = p[2]

  def p_StaticMemberRest(self, p):
    """StaticMemberRest : ReadOnly AttributeRest
                        | ReturnType OperationRest"""
    if len(p) == 2:
      p[0] = p[1]
    else:
      p[2].AddChildren(p[1])
      p[0] = p[2]

  def p_ReadonlyMember(self, p):
    """ReadonlyMember : READONLY ReadonlyMemberRest"""
    p[2].AddChildren(self.BuildTrue('READONLY'))
    p[0] = p[2]

  def p_ReadonlyMemberRest(self, p):
    """ReadonlyMemberRest : AttributeRest
                          | MaplikeRest
                          | SetlikeRest"""
    p[0] = p[1]

  def p_ReadWriteAttribute(self, p):
    """ReadWriteAttribute : INHERIT ReadOnly AttributeRest
                          | AttributeRest"""
    if len(p) > 2:
      inherit = self.BuildTrue('INHERIT')
      p[3].AddChildren(ListFromConcat(inherit, p[2]))
      p[0] = p[3]
    else:
      p[0] = p[1]

  def p_AttributeRest(self, p):
    """AttributeRest : ATTRIBUTE Type AttributeName ';'"""
    p[0] = self.BuildNamed('Attribute', p, 3, p[2])

  def p_AttributeName(self, p):
    """AttributeName : AttributeNameKeyword
                     | identifier"""
    p[0] = p[1]

  def p_AttributeNameKeyword(self, p):
    """AttributeNameKeyword : REQUIRED"""
    p[0] = p[1]

  def p_ReadOnly(self, p):
    """ReadOnly : READONLY
                |"""
    if len(p) > 1:
      p[0] = self.BuildTrue('READONLY')

  def p_Operation(self, p):
    """Operation : ReturnType OperationRest
                 | SpecialOperation"""
    if len(p) == 3:
      p[2].AddChildren(p[1])
      p[0] = p[2]
    else:
      p[0] = p[1]

  def p_SpecialOperation(self, p):
    """SpecialOperation : Special Specials ReturnType OperationRest"""
    p[4].AddChildren(ListFromConcat(p[1], p[2], p[3]))
    p[0] = p[4]

  def p_Specials(self, p):
    """Specials : Special Specials
                | """
    if len(p) > 1:
      p[0] = ListFromConcat(p[1], p[2])

  def p_Special(self, p):
    """Special : GETTER
               | SETTER
               | CREATOR
               | DELETER
               | LEGACYCALLER"""
    p[0] = self.BuildTrue(p[1].upper())

  def p_OperationRest(self, p):
    """OperationRest : OptionalIdentifier '(' ArgumentList ')' ';'"""
    arguments = self.BuildProduction('Arguments', p, 2, p[3])
    p[0] = self.BuildNamed('Operation', p, 1, arguments)

  def p_OptionalIdentifier(self, p):
    """OptionalIdentifier : identifier
                          |"""
    if len(p) > 1:
      p[0] = p[1]
    else:
      p[0] = '_unnamed_'

  def p_ArgumentList(self, p):
    """ArgumentList : Argument Arguments
                    |"""
    if len(p) > 1:
      p[0] = ListFromConcat(p[1], p[2])

  # ArgumentList error recovery
  def p_ArgumentListError(self, p):
    """ArgumentList : error """
    p[0] = self.BuildError(p, 'ArgumentList')

  def p_Arguments(self, p):
    """Arguments : ',' Argument Arguments
                 |"""
    if len(p) > 1:
      p[0] = ListFromConcat(p[2], p[3])

  # Arguments error recovery
  def p_ArgumentsError(self, p):
    """Arguments : ',' error"""
    p[0] = self.BuildError(p, 'Arguments')

  def p_Argument(self, p):
    """Argument : ExtendedAttributeList OptionalOrRequiredArgument"""
    p[2].AddChildren(p[1])
    p[0] = p[2]

  def p_OptionalOrRequiredArgument(self, p):
    """OptionalOrRequiredArgument : OPTIONAL Type ArgumentName Default
                                  | Type Ellipsis ArgumentName"""
    if len(p) > 4:
      arg = self.BuildNamed('Argument', p, 3, ListFromConcat(p[2], p[4]))
      arg.AddChildren(self.BuildTrue('OPTIONAL'))
    else:
      arg = self.BuildNamed('Argument', p, 3, ListFromConcat(p[1], p[2]))
    p[0] = arg

  def p_ArgumentName(self, p):
    """ArgumentName : ArgumentNameKeyword
                    | identifier"""
    p[0] = p[1]

  def p_Ellipsis(self, p):
    """Ellipsis : ELLIPSIS
                |"""
    if len(p) > 1:
      p[0] = self.BuildNamed('Argument', p, 1)
      p[0].AddChildren(self.BuildTrue('ELLIPSIS'))

  def p_Iterable(self, p):
    """Iterable : ITERABLE '<' Type OptionalType '>' ';'"""
    childlist = ListFromConcat(p[3], p[4])
    p[0] = self.BuildProduction('Iterable', p, 2, childlist)

  def p_OptionalType(self, p):
    """OptionalType : ',' Type
                    |"""
    if len(p) > 1:
      p[0] = p[2]

  def p_ReadWriteMaplike(self, p):
    """ReadWriteMaplike : MaplikeRest"""
    p[0] = p[1]

  def p_ReadWriteSetlike(self, p):
    """ReadWriteSetlike : SetlikeRest"""
    p[0] = p[1]

  def p_MaplikeRest(self, p):
    """MaplikeRest : MAPLIKE '<' Type ',' Type '>' ';'"""
    childlist = ListFromConcat(p[3], p[5])
    p[0] = self.BuildProduction('Maplike', p, 2, childlist)

  def p_SetlikeRest(self, p):
    """SetlikeRest : SETLIKE '<' Type '>' ';'"""
    p[0] = self.BuildProduction('Setlike', p, 2, p[3])

  def p_ExtendedAttributeList(self, p):
    """ExtendedAttributeList : '[' ExtendedAttribute ExtendedAttributes ']'
                             | """
    if len(p) > 3:
      items = ListFromConcat(p[2], p[3])
      p[0] = self.BuildProduction('ExtAttributes', p, 1, items)

  # Error recovery for ExtendedAttributeList
  def p_ExtendedAttributeListError(self, p):
    """ExtendedAttributeList : '[' ExtendedAttribute ',' error"""
    p[0] = self.BuildError(p, 'ExtendedAttributeList')

  def p_ExtendedAttributes(self, p):
    """ExtendedAttributes : ',' ExtendedAttribute ExtendedAttributes
                          |"""
    if len(p) > 1:
      p[0] = ListFromConcat(p[2], p[3])

  # https://heycam.github.io/webidl/#idl-extended-attributes
  # The ExtendedAttribute symbol in Web IDL grammar is very flexible but we
  # only support following patterns:
  #    [ identifier ]
  #    [ identifier ( ArgumentList ) ]
  #    [ identifier = identifier ]
  #    [ identifier = ( IdentifierList ) ]
  #    [ identifier = identifier ( ArgumentList ) ]
  #    [ identifier = ( StringList ) ]
  # The first five patterns are specified in the Web IDL spec and the last
  # pattern is Blink's custom extension to support [ReflectOnly].
  def p_ExtendedAttribute(self, p):
    """ExtendedAttribute : ExtendedAttributeNoArgs
                         | ExtendedAttributeArgList
                         | ExtendedAttributeIdent
                         | ExtendedAttributeIdentList
                         | ExtendedAttributeNamedArgList
                         | ExtendedAttributeStringLiteral
                         | ExtendedAttributeStringLiteralList"""
    p[0] = p[1]

  def p_ArgumentNameKeyword(self, p):
    """ArgumentNameKeyword : ATTRIBUTE
                           | CALLBACK
                           | CONST
                           | CREATOR
                           | DELETER
                           | DICTIONARY
                           | ENUM
                           | GETTER
                           | IMPLEMENTS
                           | INHERIT
                           | LEGACYCALLER
                           | PARTIAL
                           | SERIALIZER
                           | SETTER
                           | STATIC
                           | STRINGIFIER
                           | TYPEDEF
                           | UNRESTRICTED"""
    p[0] = p[1]

  def p_Type(self, p):
    """Type : SingleType
            | UnionType TypeSuffix"""
    if len(p) == 2:
      p[0] = self.BuildProduction('Type', p, 1, p[1])
    else:
      p[0] = self.BuildProduction('Type', p, 1, ListFromConcat(p[1], p[2]))

  def p_SingleType(self, p):
    """SingleType : NonAnyType
                  | ANY TypeSuffixStartingWithArray"""
    if len(p) == 2:
      p[0] = p[1]
    else:
      p[0] = ListFromConcat(self.BuildProduction('Any', p, 1), p[2])

  def p_UnionType(self, p):
    """UnionType : '(' UnionMemberType OR UnionMemberType UnionMemberTypes ')'"""
    members = ListFromConcat(p[2], p[4], p[5])
    p[0] = self.BuildProduction('UnionType', p, 1, members)

  def p_UnionMemberType(self, p):
    """UnionMemberType : NonAnyType
                       | UnionType TypeSuffix
                       | ANY '[' ']' TypeSuffix"""
    if len(p) == 2:
      p[0] = self.BuildProduction('Type', p, 1, p[1])
    elif len(p) == 3:
      p[0] = self.BuildProduction('Type', p, 1, ListFromConcat(p[1], p[2]))
    else:
      any_node = ListFromConcat(self.BuildProduction('Any', p, 1), p[4])
      p[0] = self.BuildProduction('Type', p, 1, any_node)

  def p_UnionMemberTypes(self, p):
    """UnionMemberTypes : OR UnionMemberType UnionMemberTypes
                        |"""
    if len(p) > 2:
      p[0] = ListFromConcat(p[2], p[3])

  # Moved BYTESTRING, DOMSTRING, OBJECT, DATE, REGEXP to PrimitiveType
  # Moving all built-in types into PrimitiveType makes it easier to
  # differentiate between them and 'identifier', since p[1] would be a string in
  # both cases.
  def p_NonAnyType(self, p):
    """NonAnyType : PrimitiveType TypeSuffix
                  | PromiseType Null
                  | identifier TypeSuffix
                  | SEQUENCE '<' Type '>' Null
                  | FROZENARRAY '<' Type '>' Null
                  | RecordType Null"""
    if len(p) == 3:
      if type(p[1]) == str:
        typeref = self.BuildNamed('Typeref', p, 1)
      else:
        typeref = p[1]
      p[0] = ListFromConcat(typeref, p[2])

    if len(p) == 6:
      cls = 'Sequence' if p[1] == 'sequence' else 'FrozenArray'
      p[0] = self.BuildProduction(cls, p, 1, ListFromConcat(p[3], p[5]))

  def p_ConstType(self,  p):
    """ConstType : PrimitiveType Null
                 | identifier Null"""
    if type(p[1]) == str:
      p[0] = self.BuildNamed('Typeref', p, 1, p[2])
    else:
      p[1].AddChildren(p[2])
      p[0] = p[1]


  # Added StringType, OBJECT, DATE, REGEXP
  def p_PrimitiveType(self, p):
    """PrimitiveType : UnsignedIntegerType
                     | UnrestrictedFloatType
                     | StringType
                     | BOOLEAN
                     | BYTE
                     | OCTET
                     | OBJECT
                     | DATE
                     | REGEXP"""
    if type(p[1]) == str:
      p[0] = self.BuildNamed('PrimitiveType', p, 1)
    else:
      p[0] = p[1]

  def p_UnrestrictedFloatType(self, p):
    """UnrestrictedFloatType : UNRESTRICTED FloatType
                             | FloatType"""
    if len(p) == 2:
      typeref = self.BuildNamed('PrimitiveType', p, 1)
    else:
      typeref = self.BuildNamed('PrimitiveType', p, 2)
      typeref.AddChildren(self.BuildTrue('UNRESTRICTED'))
    p[0] = typeref

  def p_FloatType(self, p):
    """FloatType : FLOAT
                 | DOUBLE"""
    p[0] = p[1]

  def p_UnsignedIntegerType(self, p):
    """UnsignedIntegerType : UNSIGNED IntegerType
                           | IntegerType"""
    if len(p) == 2:
      p[0] = p[1]
    else:
      p[0] = 'unsigned ' + p[2]

  def p_IntegerType(self, p):
    """IntegerType : SHORT
                   | LONG OptionalLong"""
    if len(p) == 2:
      p[0] = p[1]
    else:
      p[0] = p[1] + p[2]

  def p_OptionalLong(self, p):
    """OptionalLong : LONG
                    | """
    if len(p) > 1:
      p[0] = ' ' + p[1]
    else:
      p[0] = ''

  # Add unqualified Promise
  def p_PromiseType(self, p):
    """PromiseType : PROMISE '<' ReturnType '>'
                   | PROMISE"""
    if len(p) == 2:
      # Promise without resolution type is not specified in the Web IDL spec.
      # As it is used in some specs and in the blink implementation,
      # we allow that here.
      resolution_type = self.BuildProduction('Type', p, 1,
                                             self.BuildProduction('Any', p, 1))
      p[0] = self.BuildNamed('Promise', p, 1, resolution_type)
    else:
      p[0] = self.BuildNamed('Promise', p, 1, p[3])

  # Add support for sized array
  def p_TypeSuffix(self, p):
    """TypeSuffix : '[' integer ']' TypeSuffix
                  | '[' ']' TypeSuffix
                  | '?' TypeSuffixStartingWithArray
                  | """
    if len(p) == 5:
      p[0] = self.BuildNamed('Array', p, 2, p[4])

    if len(p) == 4:
      p[0] = self.BuildProduction('Array', p, 1, p[3])

    if len(p) == 3:
      p[0] = ListFromConcat(self.BuildTrue('NULLABLE'), p[2])

  def p_TypeSuffixStartingWithArray(self, p):
    """TypeSuffixStartingWithArray : '[' ']' TypeSuffix
                                   | """
    if len(p) > 1:
      p[0] = self.BuildProduction('Array', p, 0, p[3])

  def p_Null(self, p):
    """Null : '?'
            |"""
    if len(p) > 1:
      p[0] = self.BuildTrue('NULLABLE')

  def p_ReturnType(self, p):
    """ReturnType : Type
                  | VOID"""
    if p[1] == 'void':
      p[0] = self.BuildProduction('Type', p, 1)
      p[0].AddChildren(self.BuildNamed('PrimitiveType', p, 1))
    else:
      p[0] = p[1]

  def p_IdentifierList(self, p):
    """IdentifierList : identifier Identifiers"""
    p[0] = ListFromConcat(p[1], p[2])

  def p_Identifiers(self, p):
    """Identifiers : ',' identifier Identifiers
                   |"""
    if len(p) > 1:
      p[0] = ListFromConcat(p[2], p[3])

  def p_ExtendedAttributeNoArgs(self, p):
    """ExtendedAttributeNoArgs : identifier"""
    p[0] = self.BuildNamed('ExtAttribute', p, 1)

  def p_ExtendedAttributeArgList(self, p):
    """ExtendedAttributeArgList : identifier '(' ArgumentList ')'"""
    arguments = self.BuildProduction('Arguments', p, 2, p[3])
    p[0] = self.BuildNamed('ExtAttribute', p, 1, arguments)

  def p_ExtendedAttributeIdent(self, p):
    """ExtendedAttributeIdent : identifier '=' identifier"""
    value = self.BuildAttribute('VALUE', p[3])
    p[0] = self.BuildNamed('ExtAttribute', p, 1, value)

  def p_ExtendedAttributeIdentList(self, p):
    """ExtendedAttributeIdentList : identifier '=' '(' IdentifierList ')'"""
    value = self.BuildAttribute('VALUE', p[4])
    p[0] = self.BuildNamed('ExtAttribute', p, 1, value)

  def p_ExtendedAttributeNamedArgList(self, p):
    """ExtendedAttributeNamedArgList : identifier '=' identifier '(' ArgumentList ')'"""
    args = self.BuildProduction('Arguments', p, 4, p[5])
    value = self.BuildNamed('Call', p, 3, args)
    p[0] = self.BuildNamed('ExtAttribute', p, 1, value)

  # Blink extension: Add support for string literal Extended Attribute values
  def p_ExtendedAttributeStringLiteral(self, p):
    """ExtendedAttributeStringLiteral : identifier '=' StringLiteral"""
    def UnwrapString(ls):
      """Reach in and grab the string literal's "NAME"."""
      return ls[1].value

    value = self.BuildAttribute('VALUE', UnwrapString(p[3]))
    p[0] = self.BuildNamed('ExtAttribute', p, 1, value)

  # Blink extension: Add support for compound Extended Attribute values over
  # string literals ("A","B")
  def p_ExtendedAttributeStringLiteralList(self, p):
    """ExtendedAttributeStringLiteralList : identifier '=' '(' StringLiteralList ')'"""
    value = self.BuildAttribute('VALUE', p[4])
    p[0] = self.BuildNamed('ExtAttribute', p, 1, value)

  # Blink extension: One or more string literals. The values aren't propagated
  # as literals, but their by their value only.
  def p_StringLiteralList(self, p):
    """StringLiteralList : StringLiteral ',' StringLiteralList
                         | StringLiteral"""
    def UnwrapString(ls):
      """Reach in and grab the string literal's "NAME"."""
      return ls[1].value

    if len(p) > 3:
      p[0] = ListFromConcat(UnwrapString(p[1]), p[3])
    else:
      p[0] = ListFromConcat(UnwrapString(p[1]))

  # Blink extension: Wrap string literal.
  def p_StringLiteral(self, p):
    """StringLiteral : string"""
    p[0] = ListFromConcat(self.BuildAttribute('TYPE', 'DOMString'),
                          self.BuildAttribute('NAME', p[1]))

  def p_StringType(self, p):
    """StringType : BYTESTRING
                  | DOMSTRING
                  | USVSTRING"""
    p[0] = self.BuildNamed('StringType', p, 1)

  def p_RecordType(self, p):
    """RecordType : RECORD '<' StringType ',' Type '>'"""
    p[0] = self.BuildProduction('Record', p, 2, ListFromConcat(p[3], p[5]))

  # Error recovery for RecordType.
  def p_RecordTypeError(self, p):
    """RecordType : RECORD '<' error ',' Type '>'"""
    p[0] = self.BuildError(p, 'RecordType')

#
# Parser Errors
#
# p_error is called whenever the parser can not find a pattern match for
# a set of items from the current state.  The p_error function defined here
# is triggered logging an error, and parsing recovery happens as the
# p_<type>_error functions defined above are called.  This allows the parser
# to continue so as to capture more than one error per file.
#
  def p_error(self, t):
    if t:
      lineno = t.lineno
      pos = t.lexpos
      prev = self.yaccobj.symstack[-1]
      if type(prev) == lex.LexToken:
        msg = "Unexpected %s after %s." % (
            TokenTypeName(t), TokenTypeName(prev))
      else:
        msg = "Unexpected %s." % (t.value)
    else:
      last = self.LastToken()
      lineno = last.lineno
      pos = last.lexpos
      msg = "Unexpected end of file after %s." % TokenTypeName(last)
      self.yaccobj.restart()

    # Attempt to remap the error to a friendlier form
    if msg in ERROR_REMAP:
      msg = ERROR_REMAP[msg]

    self._last_error_msg = msg
    self._last_error_lineno = lineno
    self._last_error_pos = pos

  def Warn(self, node, msg):
    sys.stdout.write(node.GetLogLine(msg))
    self.parse_warnings += 1

  def LastToken(self):
    return self.lexer.last

  def __init__(self, lexer, verbose=False, debug=False, mute_error=False):
    self.lexer = lexer
    self.tokens = lexer.KnownTokens()
    self.yaccobj = yacc.yacc(module=self, tabmodule=None, debug=debug,
                             optimize=0, write_tables=0)
    self.parse_debug = debug
    self.verbose = verbose
    self.mute_error = mute_error
    self._parse_errors = 0
    self._parse_warnings = 0
    self._last_error_msg = None
    self._last_error_lineno = 0
    self._last_error_pos = 0


#
# BuildProduction
#
# Production is the set of items sent to a grammar rule resulting in a new
# item being returned.
#
# cls - The type of item being producted
# p - Is the Yacc production object containing the stack of items
# index - Index into the production of the name for the item being produced.
# childlist - The children of the new item
  def BuildProduction(self, cls, p, index, childlist=None):
    try:
      if not childlist:
        childlist = []

      filename = self.lexer.Lexer().filename
      lineno = p.lineno(index)
      pos = p.lexpos(index)
      out = IDLNode(cls, filename, lineno, pos, childlist)
      return out
    except:
      print 'Exception while parsing:'
      for num, item in enumerate(p):
        print '  [%d] %s' % (num, ExpandProduction(item))
      if self.LastToken():
        print 'Last token: %s' % str(self.LastToken())
      raise

  def BuildNamed(self, cls, p, index, childlist=None):
    childlist = ListFromConcat(childlist)
    childlist.append(self.BuildAttribute('NAME', p[index]))
    return self.BuildProduction(cls, p, index, childlist)

#
# BuildError
#
# Build and Errror node as part of the recovery process.
#
#
  def BuildError(self, p, prod):
    self._parse_errors += 1
    name = self.BuildAttribute('NAME', self._last_error_msg)
    line = self.BuildAttribute('LINE', self._last_error_lineno)
    pos = self.BuildAttribute('POS', self._last_error_pos)
    prod = self.BuildAttribute('PROD', prod)

    node = self.BuildProduction('Error', p, 1,
                                ListFromConcat(name, line, pos, prod))
    if not self.mute_error:
      node.Error(self._last_error_msg)

    return node

#
# BuildAttribute
#
# An ExtendedAttribute is a special production that results in a property
# which is applied to the adjacent item.  Attributes have no children and
# instead represent key/value pairs.
#
  def BuildAttribute(self, key, val):
    return IDLAttribute(key, val)

  def BuildFalse(self, key):
    return IDLAttribute(key, Boolean(False))

  def BuildTrue(self, key):
    return IDLAttribute(key, Boolean(True))

  def GetErrors(self):
    # Access lexer errors, despite being private
    # pylint: disable=W0212
    return self._parse_errors + self.lexer._lex_errors

#
# ParseData
#
# Attempts to parse the current data loaded in the lexer.
#
  def ParseText(self, filename, data):
    self._parse_errors = 0
    self._parse_warnings = 0
    self._last_error_msg = None
    self._last_error_lineno = 0
    self._last_error_pos = 0

    try:
      self.lexer.Tokenize(data, filename)
      nodes = self.yaccobj.parse(lexer=self.lexer) or []
      name = self.BuildAttribute('NAME', filename)
      return IDLNode('File', filename, 0, 0, nodes + [name])

    except lex.LexError as lexError:
      sys.stderr.write('Error in token: %s\n' % str(lexError))
    return None



def ParseFile(parser, filename):
  """Parse a file and return a File type of node."""
  with open(filename) as fileobject:
    try:
      out = parser.ParseText(filename, fileobject.read())
      out.SetProperty('DATETIME', time.ctime(os.path.getmtime(filename)))
      out.SetProperty('ERRORS', parser.GetErrors())
      return out

    except Exception as e:
      last = parser.LastToken()
      sys.stderr.write('%s(%d) : Internal parsing error\n\t%s.\n' % (
                       filename, last.lineno, str(e)))


def main(argv):
  nodes = []
  parser = IDLParser(IDLLexer())
  errors = 0
  for filename in argv:
    filenode = ParseFile(parser, filename)
    if (filenode):
      errors += filenode.GetProperty('ERRORS')
      nodes.append(filenode)

  ast = IDLNode('AST', '__AST__', 0, 0, nodes)

  print '\n'.join(ast.Tree(accept_props=['PROD']))
  if errors:
    print '\nFound %d errors.\n' % errors

  return errors


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))

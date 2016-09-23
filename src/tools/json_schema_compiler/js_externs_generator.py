# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""
Generator that produces an externs file for the Closure Compiler.
Note: This is a work in progress, and generated externs may require tweaking.

See https://developers.google.com/closure/compiler/docs/api-tutorial3#externs
"""

from code import Code
from js_util import JsUtil
from model import *
from schema_util import *

import os
import sys
import re

NOTE = """// NOTE: The format of types has changed. 'FooType' is now
//   'chrome.%s.FooType'.
// Please run the closure compiler before committing changes.
// See https://chromium.googlesource.com/chromium/src/+/master/docs/closure_compilation.md
"""

class JsExternsGenerator(object):
  def Generate(self, namespace):
    return _Generator(namespace).Generate()

class _Generator(object):
  def __init__(self, namespace):
    self._namespace = namespace
    self._js_util = JsUtil()

  def Generate(self):
    """Generates a Code object with the schema for the entire namespace.
    """
    c = Code()
    (c.Append(self._GetHeader(sys.argv[0], self._namespace.name))
      .Append())

    self._AppendNamespaceObject(c)

    for js_type in self._namespace.types.values():
      self._AppendType(c, js_type)

    for function in self._namespace.functions.values():
      self._AppendFunction(c, function)

    for event in self._namespace.events.values():
      self._AppendEvent(c, event)

    c.TrimTrailingNewlines()

    return c

  def _GetHeader(self, tool, namespace):
    """Returns the file header text.
    """
    return (self._js_util.GetLicense() + '\n' +
            self._js_util.GetInfo(tool) + (NOTE % namespace) + '\n' +
            ('/** @fileoverview Externs generated from namespace: %s */' %
             namespace))

  def _AppendType(self, c, js_type):
    """Given a Type object, generates the Code for this type's definition.
    """
    if js_type.property_type is PropertyType.ENUM:
      self._AppendEnumJsDoc(c, js_type)
    else:
      self._AppendTypeJsDoc(c, js_type)
    c.Append()

  def _AppendEnumJsDoc(self, c, js_type):
    """ Given an Enum Type object, generates the Code for the enum's definition.
    """
    (c.Sblock(line='/**', line_prefix=' * ')
      .Append('@enum {string}')
      .Append(self._js_util.GetSeeLink(self._namespace.name, 'type',
                                       js_type.simple_name))
      .Eblock(' */'))
    c.Append('chrome.%s.%s = {' % (self._namespace.name, js_type.name))

    def get_property_name(e):
      # Enum properties are normified to be in ALL_CAPS_STYLE.
      # Assume enum '1ring-rulesThemAll'.
      # Transform to '1ring-rules_Them_All'.
      e = re.sub(r'([a-z])([A-Z])', r'\1_\2', e)
      # Transform to '1ring_rules_Them_All'.
      e = re.sub(r'\W', '_', e)
      # Transform to '_1ring_rules_Them_All'.
      e = re.sub(r'^(\d)', r'_\1', e)
      # Transform to '_1RING_RULES_THEM_ALL'.
      return e.upper()

    c.Append('\n'.join(
        ["  %s: '%s'," % (get_property_name(v.name), v.name)
            for v in js_type.enum_values]))
    c.Append('};')

  def _IsTypeConstructor(self, js_type):
    """Returns true if the given type should be a @constructor. If this returns
       false, the type is a typedef.
    """
    return any(prop.type_.property_type is PropertyType.FUNCTION
               for prop in js_type.properties.values())

  def _AppendTypeJsDoc(self, c, js_type):
    """Appends the documentation for a type as a Code.
    """
    c.Sblock(line='/**', line_prefix=' * ')

    if js_type.description:
      for line in js_type.description.splitlines():
        c.Append(line)

    is_constructor = self._IsTypeConstructor(js_type)
    if is_constructor:
      c.Comment('@constructor', comment_prefix = ' * ', wrap_indent=4)
    else:
      self._AppendTypedef(c, js_type.properties)

    c.Append(self._js_util.GetSeeLink(self._namespace.name, 'type',
                                      js_type.simple_name))
    c.Eblock(' */')

    var = 'chrome.%s.%s' % (js_type.namespace.name, js_type.simple_name)
    if is_constructor: var += ' = function() {}'
    var += ';'
    c.Append(var)

  def _AppendTypedef(self, c, properties):
    """Given an OrderedDict of properties, Appends code containing a @typedef.
    """
    if not properties: return

    c.Append('@typedef {')
    self._js_util.AppendObjectDefinition(c, self._namespace.name, properties,
                                         new_line=False)
    c.Append('}', new_line=False)

  def _AppendFunction(self, c, function):
    """Appends the code representing a function, including its documentation.
       For example:

       /**
        * @param {string} title The new title.
        */
       chrome.window.setTitle = function(title) {};
    """
    self._js_util.AppendFunctionJsDoc(c, self._namespace.name, function)
    params = self._GetFunctionParams(function)
    c.Append('chrome.%s.%s = function(%s) {};' % (self._namespace.name,
                                                  function.name, params))
    c.Append()

  def _AppendEvent(self, c, event):
    """Appends the code representing an event.
       For example:

       /** @type {!ChromeEvent} */
       chrome.bookmarks.onChildrenReordered;
    """
    c.Sblock(line='/**', line_prefix=' * ')
    if (event.description):
      c.Comment(event.description, comment_prefix='')
    c.Append('@type {!ChromeEvent}')
    c.Append(self._js_util.GetSeeLink(self._namespace.name, 'event',
                                      event.name))
    c.Eblock(' */')
    c.Append('chrome.%s.%s;' % (self._namespace.name, event.name))
    c.Append()

  def _AppendNamespaceObject(self, c):
    """Appends the code creating namespace object.
       For example:

       /**
        * @const
        */
       chrome.bookmarks = {};
    """
    c.Append("""/**
 * @const
 */""")
    c.Append('chrome.%s = {};' % self._namespace.name)
    c.Append()

  def _GetFunctionParams(self, function):
    """Returns the function params string for function.
    """
    params = function.params[:]
    if function.callback:
      params.append(function.callback)
    return ', '.join(param.name for param in params)

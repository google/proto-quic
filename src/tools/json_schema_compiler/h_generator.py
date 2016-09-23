# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from code import Code
from model import PropertyType
import cpp_util
import schema_util

class HGenerator(object):
  def __init__(self, type_generator):
    self._type_generator = type_generator

  def Generate(self, namespace):
    return _Generator(namespace, self._type_generator).Generate()


class _Generator(object):
  """A .h generator for a namespace.
  """
  def __init__(self, namespace, cpp_type_generator):
    self._namespace = namespace
    self._type_helper = cpp_type_generator
    self._generate_error_messages = namespace.compiler_options.get(
        'generate_error_messages', False)

  def Generate(self):
    """Generates a Code object with the .h for a single namespace.
    """
    c = Code()
    (c.Append(cpp_util.CHROMIUM_LICENSE)
      .Append()
      .Append(cpp_util.GENERATED_FILE_MESSAGE % self._namespace.source_file)
      .Append()
    )

    # Hack: for the purpose of gyp the header file will always be the source
    # file with its file extension replaced by '.h'. Assume so.
    output_file = os.path.splitext(self._namespace.source_file)[0] + '.h'
    ifndef_name = cpp_util.GenerateIfndefName(output_file)

    # Hack: tabs and windows have circular references, so only generate hard
    # references for them (i.e. anything that can't be forward declared). In
    # other cases, generate soft dependencies so that they can include
    # non-optional types from other namespaces.
    include_soft = self._namespace.name not in ('tabs', 'windows')

    (c.Append('#ifndef %s' % ifndef_name)
      .Append('#define %s' % ifndef_name)
      .Append()
      .Append('#include <stdint.h>')
      .Append()
      .Append('#include <map>')
      .Append('#include <memory>')
      .Append('#include <string>')
      .Append('#include <vector>')
      .Append()
      .Append('#include "base/logging.h"')
      .Append('#include "base/values.h"')
      .Cblock(self._type_helper.GenerateIncludes(include_soft=include_soft))
      .Append()
    )

    # Hack: we're not generating soft includes for tabs and windows, so we need
    # to generate forward declarations for them.
    if not include_soft:
      c.Cblock(self._type_helper.GenerateForwardDeclarations())

    cpp_namespace = cpp_util.GetCppNamespace(
        self._namespace.environment.namespace_pattern,
        self._namespace.unix_name)
    c.Concat(cpp_util.OpenNamespace(cpp_namespace))
    c.Append()
    if self._namespace.properties:
      (c.Append('//')
        .Append('// Properties')
        .Append('//')
        .Append()
      )
      for prop in self._namespace.properties.values():
        property_code = self._type_helper.GeneratePropertyValues(
            prop,
            'extern const %(type)s %(name)s;')
        if property_code:
          c.Cblock(property_code)
    if self._namespace.types:
      (c.Append('//')
        .Append('// Types')
        .Append('//')
        .Append()
        .Cblock(self._GenerateTypes(self._FieldDependencyOrder(),
                                    is_toplevel=True,
                                    generate_typedefs=True))
      )
    if self._namespace.functions:
      (c.Append('//')
        .Append('// Functions')
        .Append('//')
        .Append()
      )
      for function in self._namespace.functions.values():
        c.Cblock(self._GenerateFunction(function))
    if self._namespace.events:
      (c.Append('//')
        .Append('// Events')
        .Append('//')
        .Append()
      )
      for event in self._namespace.events.values():
        c.Cblock(self._GenerateEvent(event))
    (c.Concat(cpp_util.CloseNamespace(cpp_namespace))
      .Append('#endif  // %s' % ifndef_name)
      .Append()
    )
    return c

  def _FieldDependencyOrder(self):
    """Generates the list of types in the current namespace in an order in which
    depended-upon types appear before types which depend on them.
    """
    dependency_order = []

    def ExpandType(path, type_):
      if type_ in path:
        raise ValueError("Illegal circular dependency via cycle " +
                         ", ".join(map(lambda x: x.name, path + [type_])))
      for prop in type_.properties.values():
        if (prop.type_ == PropertyType.REF and
            schema_util.GetNamespace(prop.ref_type) == self._namespace.name):
          ExpandType(path + [type_], self._namespace.types[prop.ref_type])
      if not type_ in dependency_order:
        dependency_order.append(type_)

    for type_ in self._namespace.types.values():
      ExpandType([], type_)
    return dependency_order

  def _GenerateEnumDeclaration(self, enum_name, type_):
    """Generate a code object with the  declaration of a C++ enum.
    """
    c = Code()
    c.Sblock('enum %s {' % enum_name)
    c.Append(self._type_helper.GetEnumNoneValue(type_) + ',')
    for value in type_.enum_values:
      current_enum_string = self._type_helper.GetEnumValue(type_, value)
      c.Append(current_enum_string + ',')
    c.Append('%s = %s,' % (
        self._type_helper.GetEnumLastValue(type_), current_enum_string))
    c.Eblock('};')
    return c

  def _GenerateFields(self, props):
    """Generates the field declarations when declaring a type.
    """
    c = Code()
    needs_blank_line = False
    for prop in props:
      if needs_blank_line:
        c.Append()
      needs_blank_line = True
      if prop.description:
        c.Comment(prop.description)
      # ANY is a base::Value which is abstract and cannot be a direct member, so
      # we always need to wrap it in a scoped_ptr.
      is_ptr = prop.optional or prop.type_.property_type == PropertyType.ANY
      (c.Append('%s %s;' % (
           self._type_helper.GetCppType(prop.type_, is_ptr=is_ptr),
           prop.unix_name))
      )
    return c

  def _GenerateType(self, type_, is_toplevel=False, generate_typedefs=False):
    """Generates a struct for |type_|.

    |is_toplevel|       implies that the type was declared in the "types" field
                        of an API schema. This determines the correct function
                        modifier(s).
    |generate_typedefs| controls whether primitive types should be generated as
                        a typedef. This may not always be desired. If false,
                        primitive types are ignored.
    """
    classname = cpp_util.Classname(schema_util.StripNamespace(type_.name))
    c = Code()

    if type_.functions:
      # Wrap functions within types in the type's namespace.
      (c.Append('namespace %s {' % classname)
        .Append()
      )
      for function in type_.functions.values():
        c.Cblock(self._GenerateFunction(function))
      c.Append('}  // namespace %s' % classname)
    elif type_.property_type == PropertyType.ARRAY:
      if generate_typedefs and type_.description:
        c.Comment(type_.description)
      c.Cblock(self._GenerateType(type_.item_type, is_toplevel=is_toplevel))
      if generate_typedefs:
        (c.Append('typedef std::vector<%s > %s;' % (
                       self._type_helper.GetCppType(type_.item_type),
                       classname))
        )
    elif type_.property_type == PropertyType.STRING:
      if generate_typedefs:
        if type_.description:
          c.Comment(type_.description)
        c.Append('typedef std::string %(classname)s;')
    elif type_.property_type == PropertyType.ENUM:
      if type_.description:
        c.Comment(type_.description)
      c.Cblock(self._GenerateEnumDeclaration(classname, type_));
      # Top level enums are in a namespace scope so the methods shouldn't be
      # static. On the other hand, those declared inline (e.g. in an object) do.
      maybe_static = '' if is_toplevel else 'static '
      (c.Append()
        .Append('%sstd::string ToString(%s as_enum);' %
                (maybe_static, classname))
        .Append('%s%s Parse%s(const std::string& as_string);' %
                (maybe_static, classname, classname))
      )
    elif type_.property_type in (PropertyType.CHOICES,
                                 PropertyType.OBJECT):
      if type_.description:
        c.Comment(type_.description)
      (c.Sblock('struct %(classname)s {')
          .Append('%(classname)s();')
          .Append('~%(classname)s();')
      )
      (c.Append('%(classname)s(%(classname)s&& rhs);')
        .Append('%(classname)s& operator=(%(classname)s&& rhs);')
      )
      if type_.origin.from_json:
        (c.Append()
          .Comment('Populates a %s object from a base::Value. Returns'
                   ' whether |out| was successfully populated.' % classname)
          .Append('static bool Populate(%s);' % self._GenerateParams(
              ('const base::Value& value', '%s* out' % classname)))
        )
        if is_toplevel:
          (c.Append()
            .Comment('Creates a %s object from a base::Value, or NULL on '
                     'failure.' % classname)
            .Append('static std::unique_ptr<%s> FromValue(%s);' % (
                classname, self._GenerateParams(('const base::Value& value',))))
          )
      if type_.origin.from_client:
        value_type = ('base::Value'
                      if type_.property_type is PropertyType.CHOICES else
                      'base::DictionaryValue')
        (c.Append()
          .Comment('Returns a new %s representing the serialized form of this '
                   '%s object.' % (value_type, classname))
          .Append('std::unique_ptr<%s> ToValue() const;' % value_type)
        )
      if type_.property_type == PropertyType.CHOICES:
        # Choices are modelled with optional fields for each choice. Exactly one
        # field of the choice is guaranteed to be set by the compiler.
        c.Cblock(self._GenerateTypes(type_.choices))
        c.Append('// Choices:')
        for choice_type in type_.choices:
          c.Append('%s as_%s;' % (
              self._type_helper.GetCppType(choice_type, is_ptr=True),
              choice_type.unix_name))
      else:
        properties = type_.properties.values()
        (c.Append()
          .Cblock(self._GenerateTypes(p.type_ for p in properties))
          .Cblock(self._GenerateFields(properties)))
        if type_.additional_properties is not None:
          # Most additionalProperties actually have type "any", which is better
          # modelled as a DictionaryValue rather than a map of string -> Value.
          if type_.additional_properties.property_type == PropertyType.ANY:
            c.Append('base::DictionaryValue additional_properties;')
          else:
            (c.Cblock(self._GenerateType(type_.additional_properties))
              .Append('std::map<std::string, %s> additional_properties;' %
                  cpp_util.PadForGenerics(
                      self._type_helper.GetCppType(type_.additional_properties,
                                                   is_in_container=True)))
            )
      (c.Eblock()
        .Append()
        .Sblock(' private:')
          .Append('DISALLOW_COPY_AND_ASSIGN(%(classname)s);')
        .Eblock('};')
      )
    return c.Substitute({'classname': classname})

  def _GenerateEvent(self, event):
    """Generates the namespaces for an event.
    """
    c = Code()
    # TODO(kalman): use event.unix_name not Classname.
    event_namespace = cpp_util.Classname(event.name)
    (c.Append('namespace %s {' % event_namespace)
      .Append()
      .Concat(self._GenerateEventNameConstant(event))
      .Concat(self._GenerateCreateCallbackArguments(event))
      .Append('}  // namespace %s' % event_namespace)
    )
    return c

  def _GenerateFunction(self, function):
    """Generates the namespaces and structs for a function.
    """
    c = Code()
    # TODO(kalman): Use function.unix_name not Classname here.
    function_namespace = cpp_util.Classname(function.name)
    # Windows has a #define for SendMessage, so to avoid any issues, we need
    # to not use the name.
    if function_namespace == 'SendMessage':
      function_namespace = 'PassMessage'
    (c.Append('namespace %s {' % function_namespace)
      .Append()
      .Cblock(self._GenerateFunctionParams(function))
    )
    if function.callback:
      c.Cblock(self._GenerateFunctionResults(function.callback))
    c.Append('}  // namespace %s' % function_namespace)
    return c

  def _GenerateFunctionParams(self, function):
    """Generates the struct for passing parameters from JSON to a function.
    """
    if not function.params:
      return Code()

    c = Code()
    (c.Sblock('struct Params {')
      .Append('static std::unique_ptr<Params> Create(%s);' %
                  self._GenerateParams(('const base::ListValue& args',)))
      .Append('~Params();')
      .Append()
      .Cblock(self._GenerateTypes(p.type_ for p in function.params))
      .Cblock(self._GenerateFields(function.params))
      .Eblock()
      .Append()
      .Sblock(' private:')
        .Append('Params();')
        .Append()
        .Append('DISALLOW_COPY_AND_ASSIGN(Params);')
      .Eblock('};')
    )
    return c

  def _GenerateTypes(self, types, is_toplevel=False, generate_typedefs=False):
    """Generate the structures required by a property such as OBJECT classes
    and enums.
    """
    c = Code()
    for type_ in types:
      c.Cblock(self._GenerateType(type_,
                                  is_toplevel=is_toplevel,
                                  generate_typedefs=generate_typedefs))
    return c

  def _GenerateCreateCallbackArguments(self, function):
    """Generates functions for passing parameters to a callback.
    """
    c = Code()
    params = function.params
    c.Cblock(self._GenerateTypes((p.type_ for p in params), is_toplevel=True))

    declaration_list = []
    for param in params:
      if param.description:
        c.Comment(param.description)
      declaration_list.append(cpp_util.GetParameterDeclaration(
          param, self._type_helper.GetCppType(param.type_)))
    c.Append('std::unique_ptr<base::ListValue> Create(%s);' %
             ', '.join(declaration_list))
    return c

  def _GenerateEventNameConstant(self, event):
    """Generates a constant string array for the event name.
    """
    c = Code()
    c.Append('extern const char kEventName[];  // "%s.%s"' % (
                 self._namespace.name, event.name))
    c.Append()
    return c

  def _GenerateFunctionResults(self, callback):
    """Generates namespace for passing a function's result back.
    """
    c = Code()
    (c.Append('namespace Results {')
      .Append()
      .Concat(self._GenerateCreateCallbackArguments(callback))
      .Append('}  // namespace Results')
    )
    return c

  def _GenerateParams(self, params):
    """Builds the parameter list for a function, given an array of parameters.
    """
    # |error| is populated with warnings and/or errors found during parsing.
    # |error| being set does not necessarily imply failure and may be
    # recoverable.
    # For example, optional properties may have failed to parse, but the
    # parser was able to continue.
    if self._generate_error_messages:
      params += ('base::string16* error',)
    return ', '.join(str(p) for p in params)

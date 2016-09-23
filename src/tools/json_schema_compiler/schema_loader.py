# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re
import sys

import idl_schema
import json_schema
from cpp_namespace_environment import CppNamespaceEnvironment
from model import Model, UnixName

def GenerateFilenames(full_namespace):
  # Try to find the file defining the namespace. Eg. for
  # nameSpace.sub_name_space.Type' the following heuristics looks for:
  # 1. name_space_sub_name_space.json,
  # 2. name_space_sub_name_space.idl,
  # 3. sub_name_space.json,
  # 4. sub_name_space.idl,
  # 5. etc.
  sub_namespaces = full_namespace.split('.')
  filenames = [ ]
  basename = None
  for namespace in reversed(sub_namespaces):
    if basename is not None:
      basename = UnixName(namespace + '.' + basename)
    else:
      basename = UnixName(namespace)
    for ext in ['json', 'idl']:
      filenames.append('%s.%s' % (basename, ext))
  return filenames

class SchemaLoader(object):
  '''Resolves a type name into the namespace the type belongs to.

  Properties:
  - |root| path to the root directory.
  - |path| path to the directory with the API header files, relative to the
    root.
  - |include_rules| List containing tuples with (path, cpp_namespace_pattern)
    used when searching for types.
  - |cpp_namespace_pattern| Default namespace pattern
  '''
  def __init__(self,
               root,
               path,
               include_rules,
               cpp_namespace_pattern):
    self._root = root
    self._include_rules = [(path, cpp_namespace_pattern)]
    self._include_rules.extend(include_rules)

  def ResolveNamespace(self, full_namespace):
    filenames = GenerateFilenames(full_namespace)
    for path, cpp_namespace in self._include_rules:
      cpp_namespace_environment = None
      if cpp_namespace:
        cpp_namespace_environment = CppNamespaceEnvironment(cpp_namespace)
      for filename in reversed(filenames):
        filepath = os.path.join(path, filename);
        if os.path.exists(os.path.join(self._root, filepath)):
          return Model().AddNamespace(
              self.LoadSchema(filepath)[0],
              filepath,
              environment=cpp_namespace_environment)
    return None

  def ResolveType(self, full_name, default_namespace):
    name_parts = full_name.rsplit('.', 1)
    if len(name_parts) == 1:
      if full_name not in default_namespace.types:
        return None
      return default_namespace
    full_namespace, type_name = full_name.rsplit('.', 1)
    namespace = self.ResolveNamespace(full_namespace)
    if namespace and type_name in namespace.types:
      return namespace
    return None

  def LoadSchema(self, schema):
    '''Load a schema definition. The schema parameter must be a file name
    with the full path relative to the root.'''
    _, schema_extension = os.path.splitext(schema)

    schema_path = os.path.join(self._root, schema)
    if schema_extension == '.json':
      api_defs = json_schema.Load(schema_path)
    elif schema_extension == '.idl':
      api_defs = idl_schema.Load(schema_path)
    else:
      sys.exit('Did not recognize file extension %s for schema %s' %
               (schema_extension, schema))

    return api_defs

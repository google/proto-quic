#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from cpp_namespace_environment import CppNamespaceEnvironment
from cpp_type_generator import CppTypeGenerator
from json_schema import CachedLoad
import idl_schema
import model
import unittest

from collections import defaultdict

class _FakeSchemaLoader(object):
  def __init__(self, model):
    self._model = model

  def ResolveType(self, type_name, default):
    parts = type_name.rsplit('.', 1)
    if len(parts) == 1:
      return default if type_name in default.types else None
    return self._model.namespaces[parts[0]]

class CppTypeGeneratorTest(unittest.TestCase):
  def setUp(self):
    self.models = defaultdict(model.Model)

    self.forbidden_json = CachedLoad('test/forbidden.json')
    self.forbidden = self.models['forbidden'].AddNamespace(
        self.forbidden_json[0], 'path/to/forbidden.json')
    self.permissions_json = CachedLoad('test/permissions.json')
    self.permissions = self.models['permissions'].AddNamespace(
        self.permissions_json[0], 'path/to/permissions.json')
    self.windows_json = CachedLoad('test/windows.json')
    self.windows = self.models['windows'].AddNamespace(self.windows_json[0],
                                                       'path/to/window.json')
    self.tabs_json = CachedLoad('test/tabs.json')
    self.tabs = self.models['tabs'].AddNamespace(self.tabs_json[0],
                                                 'path/to/tabs.json')
    self.browser_action_json = CachedLoad('test/browser_action.json')
    self.browser_action = self.models['browser_action'].AddNamespace(
        self.browser_action_json[0], 'path/to/browser_action.json')
    self.font_settings_json = CachedLoad('test/font_settings.json')
    self.font_settings = self.models['font_settings'].AddNamespace(
        self.font_settings_json[0], 'path/to/font_settings.json')
    self.dependency_tester_json = CachedLoad('test/dependency_tester.json')
    self.dependency_tester = self.models['dependency_tester'].AddNamespace(
        self.dependency_tester_json[0], 'path/to/dependency_tester.json')
    self.content_settings_json = CachedLoad('test/content_settings.json')
    self.content_settings = self.models['content_settings'].AddNamespace(
        self.content_settings_json[0], 'path/to/content_settings.json')
    self.objects_movable_idl = idl_schema.Load('test/objects_movable.idl')
    self.objects_movable = self.models['objects_movable'].AddNamespace(
        self.objects_movable_idl[0], 'path/to/objects_movable.idl',
        include_compiler_options=True)

  def testGenerateIncludesAndForwardDeclarations(self):
    m = model.Model()
    m.AddNamespace(self.windows_json[0],
                   'path/to/windows.json',
                   environment=CppNamespaceEnvironment('%(namespace)s'))
    m.AddNamespace(self.tabs_json[0],
                   'path/to/tabs.json',
                   environment=CppNamespaceEnvironment('%(namespace)s'))
    manager = CppTypeGenerator(m, _FakeSchemaLoader(m))

    self.assertEquals('', manager.GenerateIncludes().Render())
    self.assertEquals('#include "path/to/tabs.h"',
                      manager.GenerateIncludes(include_soft=True).Render())
    self.assertEquals(
        'namespace tabs {\n'
        'struct Tab;\n'
        '}  // namespace tabs',
        manager.GenerateForwardDeclarations().Render())

    m = model.Model()
    m.AddNamespace(self.windows_json[0],
                   'path/to/windows.json',
                   environment=CppNamespaceEnvironment(
                       'foo::bar::%(namespace)s'))
    m.AddNamespace(self.tabs_json[0],
                   'path/to/tabs.json',
                   environment=CppNamespaceEnvironment(
                       'foo::bar::%(namespace)s'))
    manager = CppTypeGenerator(m, _FakeSchemaLoader(m))
    self.assertEquals(
        'namespace foo {\n'
        'namespace bar {\n'
        'namespace tabs {\n'
        'struct Tab;\n'
        '}  // namespace tabs\n'
        '}  // namespace bar\n'
        '}  // namespace foo',
        manager.GenerateForwardDeclarations().Render())
    manager = CppTypeGenerator(self.models.get('permissions'),
                               _FakeSchemaLoader(m))
    self.assertEquals('', manager.GenerateIncludes().Render())
    self.assertEquals('', manager.GenerateIncludes().Render())
    self.assertEquals('', manager.GenerateForwardDeclarations().Render())
    manager = CppTypeGenerator(self.models.get('content_settings'),
                               _FakeSchemaLoader(m))
    self.assertEquals('', manager.GenerateIncludes().Render())

  def testGenerateIncludesAndForwardDeclarationsDependencies(self):
    m = model.Model()
    # Insert 'font_settings' before 'browser_action' in order to test that
    # CppTypeGenerator sorts them properly.
    m.AddNamespace(self.font_settings_json[0], 'path/to/font_settings.json')
    m.AddNamespace(self.browser_action_json[0], 'path/to/browser_action.json')
    dependency_tester = m.AddNamespace(self.dependency_tester_json[0],
                                       'path/to/dependency_tester.json')
    manager = CppTypeGenerator(m,
                               _FakeSchemaLoader(m),
                               default_namespace=dependency_tester)
    self.assertEquals('#include "path/to/browser_action.h"\n'
                      '#include "path/to/font_settings.h"',
                      manager.GenerateIncludes().Render())
    self.assertEquals('', manager.GenerateForwardDeclarations().Render())

  def testGetCppTypeSimple(self):
    manager = CppTypeGenerator(self.models.get('tabs'), _FakeSchemaLoader(None))
    self.assertEquals(
        'int',
        manager.GetCppType(self.tabs.types['Tab'].properties['id'].type_))
    self.assertEquals(
        'std::string',
        manager.GetCppType(self.tabs.types['Tab'].properties['status'].type_))
    self.assertEquals(
        'bool',
        manager.GetCppType(self.tabs.types['Tab'].properties['selected'].type_))

  def testStringAsType(self):
    manager = CppTypeGenerator(self.models.get('font_settings'),
                               _FakeSchemaLoader(None))
    self.assertEquals(
        'std::string',
        manager.GetCppType(self.font_settings.types['FakeStringType']))

  def testArrayAsType(self):
    manager = CppTypeGenerator(self.models.get('browser_action'),
                               _FakeSchemaLoader(None))
    self.assertEquals(
        'std::vector<int>',
        manager.GetCppType(self.browser_action.types['ColorArray']))

  def testGetCppTypeArray(self):
    manager = CppTypeGenerator(self.models.get('windows'),
                                _FakeSchemaLoader(None))
    self.assertEquals(
        'std::vector<Window>',
        manager.GetCppType(
            self.windows.functions['getAll'].callback.params[0].type_))
    manager = CppTypeGenerator(self.models.get('permissions'),
                               _FakeSchemaLoader(None))
    self.assertEquals(
        'std::vector<std::string>',
        manager.GetCppType(
            self.permissions.types['Permissions'].properties['origins'].type_))

    manager = CppTypeGenerator(self.models.get('objects_movable'),
                               _FakeSchemaLoader(None))
    self.assertEquals(
        'std::vector<MovablePod>',
        manager.GetCppType(
            self.objects_movable.types['MovableParent'].
                properties['pods'].type_))

  def testGetCppTypeLocalRef(self):
    manager = CppTypeGenerator(self.models.get('tabs'), _FakeSchemaLoader(None))
    self.assertEquals(
        'Tab',
        manager.GetCppType(self.tabs.functions['get'].callback.params[0].type_))

  def testGetCppTypeIncludedRef(self):
    m = model.Model()
    m.AddNamespace(self.windows_json[0],
                   'path/to/windows.json',
                   environment=CppNamespaceEnvironment('%(namespace)s'))
    m.AddNamespace(self.tabs_json[0],
                   'path/to/tabs.json',
                   environment=CppNamespaceEnvironment('%(namespace)s'))
    manager = CppTypeGenerator(m, _FakeSchemaLoader(m))
    self.assertEquals(
        'std::vector<tabs::Tab>',
        manager.GetCppType(
            self.windows.types['Window'].properties['tabs'].type_))

  def testGetCppTypeWithPadForGeneric(self):
    manager = CppTypeGenerator(self.models.get('permissions'),
                               _FakeSchemaLoader(None))
    self.assertEquals('std::vector<std::string>',
        manager.GetCppType(
            self.permissions.types['Permissions'].properties['origins'].type_,
            is_in_container=False))
    self.assertEquals('std::vector<std::string>',
        manager.GetCppType(
            self.permissions.types['Permissions'].properties['origins'].type_,
            is_in_container=True))
    self.assertEquals('bool',
        manager.GetCppType(
            self.permissions.functions['contains'].callback.params[0].type_,
        is_in_container=True))

if __name__ == '__main__':
  unittest.main()

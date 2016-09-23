# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import copy
from datetime import datetime
from functools import partial
import os

from code import Code
import json_parse

# The template for the header file of the generated FeatureProvider.
HEADER_FILE_TEMPLATE = """
// Copyright %(year)s The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GENERATED FROM THE FEATURES FILE:
//   %(source_files)s
// DO NOT EDIT.

#ifndef %(header_guard)s
#define %(header_guard)s

#include "extensions/common/features/base_feature_provider.h"

namespace extensions {

class %(provider_class)s : public BaseFeatureProvider {
 public:
  %(provider_class)s();
  ~%(provider_class)s() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(%(provider_class)s);
};

}  // namespace extensions

#endif  // %(header_guard)s
"""

# The beginning of the .cc file for the generated FeatureProvider.
CC_FILE_BEGIN = """
// Copyright %(year)s The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GENERATED FROM THE FEATURES FILE:
//   %(source_files)s
// DO NOT EDIT.

#include "%(header_file_path)s"

#include "extensions/common/features/api_feature.h"
#include "extensions/common/features/behavior_feature.h"
#include "extensions/common/features/complex_feature.h"
#include "extensions/common/features/manifest_feature.h"
#include "extensions/common/features/permission_feature.h"

namespace extensions {

"""

# The end of the .cc file for the generated FeatureProvider.
CC_FILE_END = """
%(provider_class)s::~%(provider_class)s() {}

}  // namespace extensions
"""

# A "grammar" for what is and isn't allowed in the features.json files. This
# grammar has to list all possible keys and the requirements for each. The
# format of each entry is:
#   'key': {
#     allowed_type_1: optional_properties,
#     allowed_type_2: optional_properties,
#   }
# |allowed_types| are the types of values that can be used for a given key. The
# possible values are list, unicode, bool, and int.
# |optional_properties| provide more restrictions on the given type. The options
# are:
#   'subtype': Only applicable for lists. If provided, this enforces that each
#              entry in the list is of the specified type.
#   'enum_map': A map of strings to C++ enums. When the compiler sees the given
#               enum string, it will replace it with the C++ version in the
#               compiled code. For instance, if a feature specifies
#               'channel': 'stable', the generated C++ will assign
#               version_info::Channel::STABLE to channel. The keys in this map
#               also serve as a list all of possible values.
#   'allow_all': Only applicable for lists. If present, this will check for
#                a value of "all" for a list value, and will replace it with
#                the collection of all possible values. For instance, if a
#                feature specifies 'contexts': 'all', the generated C++ will
#                assign the list of Feature::BLESSED_EXTENSION_CONTEXT,
#                Feature::BLESSED_WEB_PAGE_CONTEXT et al for contexts. If not
#                specified, defaults to false.
#   'values': A list of all possible allowed values for a given key.
# If a type definition does not have any restrictions (beyond the type itself),
# an empty definition ({}) is used.
FEATURE_GRAMMAR = (
  {
    'blacklist': {
      list: {'subtype': unicode}
    },
    'channel': {
      unicode: {
        'enum_map': {
          'trunk': 'version_info::Channel::UNKNOWN',
          'canary': 'version_info::Channel::CANARY',
          'dev': 'version_info::Channel::DEV',
          'beta': 'version_info::Channel::BETA',
          'stable': 'version_info::Channel::STABLE',
        }
      }
    },
    'command_line_switch': {
      unicode: {}
    },
    'component_extensions_auto_granted': {
      bool: {}
    },
    'contexts': {
      list: {
        'enum_map': {
          'blessed_extension': 'Feature::BLESSED_EXTENSION_CONTEXT',
          'blessed_web_page': 'Feature::BLESSED_WEB_PAGE_CONTEXT',
          'content_script': 'Feature::CONTENT_SCRIPT_CONTEXT',
          'extension_service_worker': 'Feature::SERVICE_WORKER_CONTEXT',
          'web_page': 'Feature::WEB_PAGE_CONTEXT',
          'webui': 'Feature::WEBUI_CONTEXT',
          'unblessed_extension': 'Feature::UNBLESSED_EXTENSION_CONTEXT',
        },
        'allow_all': True
      },
    },
    'default_parent': {
      bool: {'values': [True]}
    },
    'dependencies': {
      list: {'subtype': unicode}
    },
    'extension_types': {
      list: {
        'enum_map': {
          'extension': 'Manifest::TYPE_EXTENSION',
          'hosted_app': 'Manifest::TYPE_HOSTED_APP',
          'legacy_packaged_app': 'Manifest::TYPE_LEGACY_PACKAGED_APP',
          'platform_app': 'Manifest::TYPE_PLATFORM_APP',
          'shared_module': 'Manifest::TYPE_SHARED_MODULE',
          'theme': 'Manifest::TYPE_THEME',
        },
        'allow_all': True
      },
    },
    'location': {
      unicode: {
        'enum_map': {
          'component': 'SimpleFeature::COMPONENT_LOCATION',
          'external_component': 'SimpleFeature::EXTERNAL_COMPONENT_LOCATION',
          'policy': 'SimpleFeature::POLICY_LOCATION',
        }
      }
    },
    'internal': {
      bool: {'values': [True]}
    },
    'matches': {
      list: {'subtype': unicode}
    },
    'max_manifest_version': {
      int: {'values': [1]}
    },
    'min_manifest_version': {
      int: {'values': [2]}
    },
    'noparent': {
      bool: {'values': [True]}
    },
    'platforms': {
      list: {
        'enum_map': {
          'chromeos': 'Feature::CHROMEOS_PLATFORM',
          'linux': 'Feature::LINUX_PLATFORM',
          'mac': 'Feature::MACOSX_PLATFORM',
          'win': 'Feature::WIN_PLATFORM',
        }
      }
    },
    'session_types': {
      list: {
        'enum_map': {
          'regular': 'FeatureSessionType::REGULAR',
          'kiosk': 'FeatureSessionType::KIOSK',
        }
      }
    },
    'whitelist': {
      list: {'subtype': unicode}
    },
  })

FEATURE_CLASSES = ['APIFeature', 'BehaviorFeature',
                   'ManifestFeature', 'PermissionFeature']

def HasProperty(property_name, value):
  return property_name in value

def HasAtLeastOneProperty(property_names, value):
  return any([HasProperty(name, value) for name in property_names])

def DoesNotHaveProperty(property_name, value):
  return property_name not in value

VALIDATION = ({
  'all': [
    (partial(HasAtLeastOneProperty, ['channel', 'dependencies']),
     'Features must specify either a channel or dependencies'),
  ],
  'APIFeature': [
    (partial(HasProperty, 'contexts'),
     'APIFeatures must specify at least one context')
  ],
  'ManifestFeature': [
    (partial(HasProperty, 'extension_types'),
     'ManifestFeatures must specify at least one extension type'),
    (partial(DoesNotHaveProperty, 'contexts'),
     'ManifestFeatures do not support contexts.'),
  ],
  'BehaviorFeature': [],
  'PermissionFeature': [
    (partial(HasProperty, 'extension_types'),
     'PermissionFeatures must specify at least one extension type'),
    (partial(DoesNotHaveProperty, 'contexts'),
     'PermissionFeatures do not support contexts.'),
  ],
})

# These keys are used to find the parents of different features, but are not
# compiled into the features themselves.
IGNORED_KEYS = ['default_parent']

# By default, if an error is encountered, assert to stop the compilation. This
# can be disabled for testing.
ENABLE_ASSERTIONS = True

# JSON parsing returns all strings of characters as unicode types. For testing,
# we can enable converting all string types to unicode to avoid writing u''
# everywhere.
STRINGS_TO_UNICODE = False

class Feature(object):
  """A representation of a single simple feature that can handle all parsing,
  validation, and code generation.
  """
  def __init__(self, name):
    self.name = name
    self.has_parent = False
    self.errors = []
    self.feature_values = {}

  def _GetType(self, value):
    """Returns the type of the given value. This can be different than type() if
    STRINGS_TO_UNICODE is enabled.
    """
    t = type(value)
    if not STRINGS_TO_UNICODE:
      return t
    if t is str:
      return unicode
    return t

  def _AddError(self, error):
    """Adds an error to the feature. If ENABLE_ASSERTIONS is active, this will
    also assert to stop the compilation process (since errors should never be
    found in production).
    """
    self.errors.append(error)
    if ENABLE_ASSERTIONS:
      assert False, error

  def _AddKeyError(self, key, error):
    """Adds an error relating to a particular key in the feature.
    """
    self._AddError('Error parsing feature "%s" at key "%s": %s' %
                       (self.name, key, error))

  def _GetCheckedValue(self, key, expected_type, expected_values,
                       enum_map, value):
    """Returns a string to be used in the generated C++ code for a given key's
    python value, or None if the value is invalid. For example, if the python
    value is True, this returns 'true', for a string foo, this returns "foo",
    and for an enum, this looks up the C++ definition in the enum map.
      key: The key being parsed.
      expected_type: The expected type for this value, or None if any type is
                     allowed.
      expected_values: The list of allowed values for this value, or None if any
                       value is allowed.
      enum_map: The map from python value -> cpp value for all allowed values,
               or None if no special mapping should be made.
      value: The value to check.
    """
    valid = True
    if expected_values and value not in expected_values:
      self._AddKeyError(key, 'Illegal value: "%s"' % value)
      valid = False

    t = self._GetType(value)
    if expected_type and t is not expected_type:
      self._AddKeyError(key, 'Illegal value: "%s"' % value)
      valid = False

    if not valid:
      return None

    if enum_map:
      return enum_map[value]

    if t in [str, unicode]:
      return '"%s"' % str(value)
    if t is int:
      return str(value)
    if t is bool:
      return 'true' if value else 'false'
    assert False, 'Unsupported type: %s' % value

  def _ParseKey(self, key, value, grammar):
    """Parses the specific key according to the grammar rule for that key if it
    is present in the json value.
      key: The key to parse.
      value: The full value for this feature.
      grammar: The rule for the specific key.
    """
    if key not in value:
      return
    v = value[key]

    is_all = False
    if v == 'all' and list in grammar and 'allow_all' in grammar[list]:
      v = []
      is_all = True

    value_type = self._GetType(v)
    if value_type not in grammar:
      self._AddKeyError(key, 'Illegal value: "%s"' % v)
      return

    expected = grammar[value_type]
    expected_values = None
    enum_map = None
    if 'values' in expected:
      expected_values = expected['values']
    elif 'enum_map' in expected:
      enum_map = expected['enum_map']
      expected_values = enum_map.keys()

    if is_all:
      v = copy.deepcopy(expected_values)

    expected_type = None
    if value_type is list and 'subtype' in expected:
      expected_type = expected['subtype']

    cpp_value = None
    # If this value is a list, iterate over each entry and validate. Otherwise,
    # validate the single value.
    if value_type is list:
      cpp_value = []
      for sub_value in v:
        cpp_sub_value = self._GetCheckedValue(key, expected_type,
                                              expected_values, enum_map,
                                              sub_value)
        if cpp_sub_value:
          cpp_value.append(cpp_sub_value)
      if cpp_value:
        cpp_value = '{' + ','.join(cpp_value) + '}'
    else:
      cpp_value = self._GetCheckedValue(key, expected_type, expected_values,
                                        enum_map, v)

    if cpp_value:
      self.feature_values[key] = cpp_value
    elif key in self.feature_values:
      # If the key is empty and this feature inherited a value from its parent,
      # remove the inherited value.
      del self.feature_values[key]

  def SetParent(self, parent):
    """Sets the parent of this feature, and inherits all properties from that
    parent.
    """
    assert not self.feature_values, 'Parents must be set before parsing'
    self.feature_values = copy.deepcopy(parent.feature_values)
    self.has_parent = True

  def Parse(self, parsed_json):
    """Parses the feature from the given json value."""
    for key in parsed_json.keys():
      if key not in FEATURE_GRAMMAR:
        self._AddKeyError(key, 'Unrecognized key')
    for key, key_grammar in FEATURE_GRAMMAR.iteritems():
      self._ParseKey(key, parsed_json, key_grammar)

  def Validate(self, feature_class):
    for validator, error in (VALIDATION[feature_class] + VALIDATION['all']):
      if not validator(self.feature_values):
        self._AddError(error)

  def GetCode(self, feature_class):
    """Returns the Code object for generating this feature."""
    c = Code()
    c.Append('%s* feature = new %s();' % (feature_class, feature_class))
    c.Append('feature->set_name("%s");' % self.name)
    for key in sorted(self.feature_values.keys()):
      if key in IGNORED_KEYS:
        continue;
      c.Append('feature->set_%s(%s);' % (key, self.feature_values[key]))
    return c

class FeatureCompiler(object):
  """A compiler to load, parse, and generate C++ code for a number of
  features.json files."""
  def __init__(self, chrome_root, source_files, feature_class,
               provider_class, out_root, out_base_filename):
    # See __main__'s ArgumentParser for documentation on these properties.
    self._chrome_root = chrome_root
    self._source_files = source_files
    self._feature_class = feature_class
    self._provider_class = provider_class
    self._out_root = out_root
    self._out_base_filename = out_base_filename

    # The json value for the feature files.
    self._json = {}
    # The parsed features.
    self._features = {}

  def _Load(self):
    """Loads and parses the source from each input file and puts the result in
    self._json."""
    for f in self._source_files:
      abs_source_file = os.path.join(self._chrome_root, f)
      try:
        with open(abs_source_file, 'r') as f:
          f_json = json_parse.Parse(f.read())
      except:
        print('FAILED: Exception encountered while loading "%s"' %
                  abs_source_file)
        raise
      dupes = set(f_json) & set(self._json)
      assert not dupes, 'Duplicate keys found: %s' % list(dupes)
      self._json.update(f_json)

  def _FindParent(self, feature_name, feature_value):
    """Checks to see if a feature has a parent. If it does, returns the
    parent."""
    no_parent = False
    if type(feature_value) is list:
      no_parent_values = ['noparent' in v for v in feature_value]
      no_parent = all(no_parent_values)
      assert no_parent or not any(no_parent_values), (
              '"%s:" All child features must contain the same noparent value' %
                  feature_name)
    else:
      no_parent = 'noparent' in feature_value
    sep = feature_name.rfind('.')
    if sep is -1 or no_parent:
      return None

    parent_name = feature_name[:sep]
    while sep != -1 and parent_name not in self._features:
      # This recursion allows for a feature to have a parent that isn't a direct
      # ancestor. For instance, we could have feature 'alpha', and feature
      # 'alpha.child.child', where 'alpha.child.child' inherits from 'alpha'.
      # TODO(devlin): Is this useful? Or logical?
      sep = feature_name.rfind('.', 0, sep)
      parent_name = feature_name[:sep]

    if sep == -1:
      # TODO(devlin): It'd be kind of nice to be able to assert that the
      # deduced parent name is in our features, but some dotted features don't
      # have parents and also don't have noparent, e.g. system.cpu. We should
      # probably just noparent them so that we can assert this.
      #   raise KeyError('Could not find parent "%s" for feature "%s".' %
      #                      (parent_name, feature_name))
      return None
    parent_value = self._features[parent_name]
    parent = parent_value
    if type(parent_value) is list:
      for p in parent_value:
        if 'default_parent' in p.feature_values:
          parent = p
          break
      assert parent, 'No default parent found for %s' % parent_name
    return parent

  def _CompileFeature(self, feature_name, feature_value):
    """Parses a single feature."""
    if 'nocompile' in feature_value:
      assert feature_value['nocompile'], (
          'nocompile should only be true; otherwise omit this key.')
      return

    def parse_and_validate(name, value, parent):
      try:
        feature = Feature(name)
        if parent:
          feature.SetParent(parent)
        feature.Parse(value)
        feature.Validate(self._feature_class)
        return feature
      except:
        print('Failure to parse feature "%s"' % feature_name)
        raise

    parent = self._FindParent(feature_name, feature_value)
    # Handle complex features, which are lists of simple features.
    if type(feature_value) is list:
      feature_list = []
      # This doesn't handle nested complex features. I think that's probably for
      # the best.
      for v in feature_value:
        feature_list.append(parse_and_validate(feature_name, v, parent))
      self._features[feature_name] = feature_list
      return

    self._features[feature_name] = parse_and_validate(
                                       feature_name, feature_value, parent)

  def Compile(self):
    """Parses all features after loading the input files."""
    self._Load();
    # Iterate over in sorted order so that parents come first.
    for k in sorted(self._json.keys()):
      self._CompileFeature(k, self._json[k])

  def Render(self):
    """Returns the Code object for the body of the .cc file, which handles the
    initialization of all features."""
    c = Code()
    c.Append('%s::%s() {' % (self._provider_class, self._provider_class))
    c.Sblock()
    for k in sorted(self._features.keys()):
      c.Sblock('{')
      feature = self._features[k]
      if type(feature) is list:
        c.Append('std::vector<Feature*> features;')
        for f in feature:
          c.Sblock('{')
          c.Concat(f.GetCode(self._feature_class))
          c.Append('features.push_back(feature);')
          c.Eblock('}')
        c.Append('ComplexFeature* feature(new ComplexFeature(&features));')
        c.Append('feature->set_name("%s");' % k)
      else:
        c.Concat(feature.GetCode(self._feature_class))
      c.Append('AddFeature("%s", feature);' % k)
      c.Eblock('}')
    c.Eblock('}')
    return c

  def Write(self):
    """Writes the output."""
    header_file_path = self._out_base_filename + '.h'
    cc_file_path = self._out_base_filename + '.cc'
    substitutions = ({
        'header_file_path': header_file_path,
        'header_guard': (header_file_path.replace('/', '_').
                             replace('.', '_').upper()),
        'provider_class': self._provider_class,
        'source_files': str(self._source_files),
        'year': str(datetime.now().year)
    })
    if not os.path.exists(self._out_root):
      os.makedirs(self._out_root)
    # Write the .h file.
    with open(os.path.join(self._out_root, header_file_path), 'w') as f:
      header_file = Code()
      header_file.Append(HEADER_FILE_TEMPLATE)
      header_file.Substitute(substitutions)
      f.write(header_file.Render().strip())
    # Write the .cc file.
    with open(os.path.join(self._out_root, cc_file_path), 'w') as f:
      cc_file = Code()
      cc_file.Append(CC_FILE_BEGIN)
      cc_file.Substitute(substitutions)
      cc_file.Concat(self.Render())
      cc_end = Code()
      cc_end.Append(CC_FILE_END)
      cc_end.Substitute(substitutions)
      cc_file.Concat(cc_end)
      f.write(cc_file.Render().strip())

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Compile json feature files')
  parser.add_argument('chrome_root', type=str,
                      help='The root directory of the chrome checkout')
  parser.add_argument(
      'feature_class', type=str,
      help='The name of the class to use in feature generation ' +
               '(e.g. APIFeature, PermissionFeature)')
  parser.add_argument('provider_class', type=str,
                      help='The name of the class for the feature provider')
  parser.add_argument('out_root', type=str,
                      help='The root directory to generate the C++ files into')
  parser.add_argument(
      'out_base_filename', type=str,
      help='The base filename for the C++ files (.h and .cc will be appended)')
  parser.add_argument('source_files', type=str, nargs='+',
                      help='The source features.json files')
  args = parser.parse_args()
  if args.feature_class not in FEATURE_CLASSES:
    raise NameError('Unknown feature class: %s' % args.feature_class)
  c = FeatureCompiler(args.chrome_root, args.source_files, args.feature_class,
                      args.provider_class, args.out_root,
                      args.out_base_filename)
  c.Compile()
  c.Write()

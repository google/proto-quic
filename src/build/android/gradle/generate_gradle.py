#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Generates an Android Studio project from a GN target."""

import argparse
import codecs
import glob
import logging
import os
import re
import shutil
import subprocess
import sys
import zipfile

_BUILD_ANDROID = os.path.join(os.path.dirname(__file__), os.pardir)
sys.path.append(_BUILD_ANDROID)
import devil_chromium
from devil.utils import run_tests_helper
from pylib import constants
from pylib.constants import host_paths

sys.path.append(os.path.join(_BUILD_ANDROID, 'gyp'))
import jinja_template
from util import build_utils


_DEFAULT_ANDROID_MANIFEST_PATH = os.path.join(
    host_paths.DIR_SOURCE_ROOT, 'build', 'android', 'AndroidManifest.xml')
_FILE_DIR = os.path.dirname(__file__)
_SRCJARS_SUBDIR = 'extracted-srcjars'
_JNI_LIBS_SUBDIR = 'symlinked-libs'
_ARMEABI_SUBDIR = 'armeabi'
_RES_SUBDIR = 'extracted-res'
_GRADLE_BUILD_FILE = 'build.gradle'
# This needs to come first alphabetically among all modules.
_MODULE_ALL = '_all'

_DEFAULT_TARGETS = [
    # TODO(agrieve): .build_config seem not quite right for this target
    # because it has resources as deps of android_apk() rather than using an
    #  android_library() intermediate target.
    # '//android_webview:system_webview_apk',
    '//android_webview/test/embedded_test_server:aw_net_test_support_apk',
    '//android_webview/test:webview_instrumentation_apk',
    '//android_webview/test:webview_instrumentation_test_apk',
    '//base:base_junit_tests',
    '//chrome/android:chrome_junit_tests',
    '//chrome/android:chrome_public_apk',
    '//chrome/android:chrome_public_test_apk',
    '//chrome/android:chrome_sync_shell_apk',
    '//chrome/android:chrome_sync_shell_test_apk',
    '//content/public/android:content_junit_tests',
    '//content/shell/android:content_shell_apk',
]


def _TemplatePath(name):
  return os.path.join(_FILE_DIR, '{}.jinja'.format(name))


def _RebasePath(path_or_list, new_cwd=None, old_cwd=None):
  """Makes the given path(s) relative to new_cwd, or absolute if not specified.

  If new_cwd is not specified, absolute paths are returned.
  If old_cwd is not specified, constants.GetOutDirectory() is assumed.
  """
  if path_or_list is None:
    return []
  if not isinstance(path_or_list, basestring):
    return [_RebasePath(p, new_cwd, old_cwd) for p in path_or_list]
  if old_cwd is None:
    old_cwd = constants.GetOutDirectory()
  old_cwd = os.path.abspath(old_cwd)
  if new_cwd:
    new_cwd = os.path.abspath(new_cwd)
    return os.path.relpath(os.path.join(old_cwd, path_or_list), new_cwd)
  return os.path.abspath(os.path.join(old_cwd, path_or_list))


def _IsSubpathOf(child, parent):
  """Returns whether |child| is a subpath of |parent|."""
  return not os.path.relpath(child, parent).startswith(os.pardir)


def _WriteFile(path, data):
  """Writes |data| to |path|, constucting parent directories if necessary."""
  logging.info('Writing %s', path)
  dirname = os.path.dirname(path)
  if not os.path.exists(dirname):
    os.makedirs(dirname)
  with codecs.open(path, 'w', 'utf-8') as output_file:
    output_file.write(data)


def _ReadPropertiesFile(path):
  with open(path) as f:
    return dict(l.rstrip().split('=', 1) for l in f if '=' in l)


def _RunNinja(output_dir, args):
  cmd = ['ninja', '-C', output_dir, '-j1000']
  cmd.extend(args)
  logging.info('Running: %r', cmd)
  subprocess.check_call(cmd)


def _QueryForAllGnTargets(output_dir):
  # Query ninja rather than GN since it's faster.
  cmd = ['ninja', '-C', output_dir, '-t', 'targets']
  logging.info('Running: %r', cmd)
  ninja_output = build_utils.CheckOutput(cmd)
  ret = []
  SUFFIX_LEN = len('__build_config')
  for line in ninja_output.splitlines():
    ninja_target = line.rsplit(':', 1)[0]
    # Ignore root aliases by ensure a : exists.
    if ':' in ninja_target and ninja_target.endswith('__build_config'):
      ret.append('//' + ninja_target[:-SUFFIX_LEN])
  return ret


class _ProjectEntry(object):
  """Helper class for project entries."""

  _cached_entries = {}

  def __init__(self, gn_target):
    # Use _ProjectEntry.FromGnTarget instead for caching.
    self._gn_target = gn_target
    self._build_config = None
    self._java_files = None
    self._all_entries = None
    self.android_test_entry = None

  @classmethod
  def FromGnTarget(cls, gn_target):
    assert gn_target.startswith('//'), gn_target
    if ':' not in gn_target:
      gn_target = '%s:%s' % (gn_target, os.path.basename(gn_target))
    if gn_target not in cls._cached_entries:
      cls._cached_entries[gn_target] = cls(gn_target)
    return cls._cached_entries[gn_target]

  @classmethod
  def FromBuildConfigPath(cls, path):
    prefix = 'gen/'
    suffix = '.build_config'
    assert path.startswith(prefix) and path.endswith(suffix), path
    subdir = path[len(prefix):-len(suffix)]
    gn_target = '//%s:%s' % (os.path.split(subdir))
    return cls.FromGnTarget(gn_target)

  def __hash__(self):
    return hash(self._gn_target)

  def __eq__(self, other):
    return self._gn_target == other.GnTarget()

  def GnTarget(self):
    return self._gn_target

  def NinjaTarget(self):
    return self._gn_target[2:]

  def GnBuildConfigTarget(self):
    return '%s__build_config' % self._gn_target

  def NinjaBuildConfigTarget(self):
    return '%s__build_config' % self.NinjaTarget()

  def GradleSubdir(self):
    """Returns the output subdirectory."""
    return self.NinjaTarget().replace(':', os.path.sep)

  def ProjectName(self):
    """Returns the Gradle project name."""
    return self.GradleSubdir().replace(os.path.sep, '>')

  def BuildConfig(self):
    """Reads and returns the project's .build_config JSON."""
    if not self._build_config:
      path = os.path.join('gen', self.GradleSubdir() + '.build_config')
      self._build_config = build_utils.ReadJson(_RebasePath(path))
    return self._build_config

  def DepsInfo(self):
    return self.BuildConfig()['deps_info']

  def Gradle(self):
    return self.BuildConfig()['gradle']

  def Javac(self):
    return self.BuildConfig()['javac']

  def GetType(self):
    """Returns the target type from its .build_config."""
    return self.DepsInfo()['type']

  def IsValid(self):
    return self.GetType() in ('android_apk', 'java_library', 'java_binary')

  def ResZips(self):
    return self.DepsInfo().get('owned_resources_zips', [])

  def ResDirs(self):
    return self.DepsInfo().get('owned_resources_dirs', [])

  def JavaFiles(self):
    if self._java_files is None:
      java_sources_file = self.DepsInfo().get('java_sources_file')
      java_files = []
      if java_sources_file:
        java_sources_file = _RebasePath(java_sources_file)
        java_files = build_utils.ReadSourcesList(java_sources_file)
      self._java_files = java_files
    return self._java_files

  def GeneratedJavaFiles(self):
    return [p for p in self.JavaFiles() if not p.startswith('..')]

  def PrebuiltJars(self):
    return self.Gradle().get('dependent_prebuilt_jars', [])

  def AllEntries(self):
    """Returns a list of all entries that the current entry depends on.

    This includes the entry itself to make iterating simpler."""
    if self._all_entries is None:
      logging.debug('Generating entries for %s', self.GnTarget())
      deps = [_ProjectEntry.FromBuildConfigPath(p)
          for p in self.Gradle()['dependent_android_projects']]
      deps.extend(_ProjectEntry.FromBuildConfigPath(p)
          for p in self.Gradle()['dependent_java_projects'])
      all_entries = set()
      for dep in deps:
        all_entries.update(dep.AllEntries())
      all_entries.add(self)
      self._all_entries = list(all_entries)
    return self._all_entries


class _ProjectContextGenerator(object):
  """Helper class to generate gradle build files"""
  def __init__(self, project_dir, build_vars, use_gradle_process_resources,
      jinja_processor, split_projects):
    self.project_dir = project_dir
    self.build_vars = build_vars
    self.use_gradle_process_resources = use_gradle_process_resources
    self.jinja_processor = jinja_processor
    self.split_projects = split_projects
    self.processed_java_dirs = set()
    self.processed_prebuilts = set()
    self.processed_res_dirs = set()

  def _GenJniLibs(self, root_entry):
    libraries = []
    for entry in self._GetEntries(root_entry):
      libraries += entry.BuildConfig().get('native', {}).get('libraries', [])
    if libraries:
      return _CreateJniLibsDir(constants.GetOutDirectory(),
          self.EntryOutputDir(root_entry), libraries)
    return []

  def _GenJavaDirs(self, root_entry):
    java_files = []
    for entry in self._GetEntries(root_entry):
      java_files += entry.JavaFiles()
    java_dirs, excludes = _ComputeJavaSourceDirsAndExcludes(
        constants.GetOutDirectory(), java_files)
    return java_dirs, excludes

  def _GenCustomManifest(self, entry):
    """Returns the path to the generated AndroidManifest.xml.

    Gradle uses package id from manifest when generating R.class. So, we need
    to generate a custom manifest if we let gradle process resources. We cannot
    simply set android.defaultConfig.applicationId because it is not supported
    for library targets."""
    resource_packages = entry.Javac().get('resource_packages')
    if not resource_packages:
      logging.debug('Target ' + entry.GnTarget() + ' includes resources from '
          'unknown package. Unable to process with gradle.')
      return _DEFAULT_ANDROID_MANIFEST_PATH
    elif len(resource_packages) > 1:
      logging.debug('Target ' + entry.GnTarget() + ' includes resources from '
          'multiple packages. Unable to process with gradle.')
      return _DEFAULT_ANDROID_MANIFEST_PATH

    variables = {}
    variables['compile_sdk_version'] = self.build_vars['android_sdk_version']
    variables['package'] = resource_packages[0]

    output_file = os.path.join(
        self.EntryOutputDir(entry), 'AndroidManifest.xml')
    data = self.jinja_processor.Render(_TemplatePath('manifest'), variables)
    _WriteFile(output_file, data)

    return output_file

  def _Relativize(self, entry, paths):
    return _RebasePath(paths, self.EntryOutputDir(entry))

  def _Srcjars(self, entry):
    srcjars = _RebasePath(entry.Gradle().get('bundled_srcjars', []))
    if not self.use_gradle_process_resources:
      srcjars += _RebasePath(entry.Javac()['srcjars'])
      srcjars += _RebasePath(entry.Gradle().get('srcjars'))
    return srcjars

  def _GetEntries(self, entry):
    if self.split_projects:
      return [entry]
    return entry.AllEntries()

  def EntryOutputDir(self, entry):
    return os.path.join(self.project_dir, entry.GradleSubdir())

  def AllSrcjars(self, root_entry):
    srcjars = []
    for entry in self._GetEntries(root_entry):
      srcjars += self._Srcjars(entry)
    return set(srcjars)

  def AllResZips(self, root_entry):
    res_zips = []
    for entry in self._GetEntries(root_entry):
      res_zips += entry.ResZips()
    return set(_RebasePath(res_zips))

  def GeneratedInputs(self, root_entry):
    generated_inputs = set(self.AllResZips(root_entry))
    generated_inputs.update(self.AllSrcjars(root_entry))
    for entry in self._GetEntries(root_entry):
      generated_inputs.update(entry.GeneratedJavaFiles())
      generated_inputs.update(entry.PrebuiltJars())
    return set(generated_inputs)

  def Generate(self, root_entry):
    # TODO(agrieve): Add an option to use interface jars and see if that speeds
    # things up at all.
    variables = {}
    java_dirs, excludes = self._GenJavaDirs(root_entry)
    java_dirs.append(
        os.path.join(self.EntryOutputDir(root_entry), _SRCJARS_SUBDIR))
    self.processed_java_dirs.update(java_dirs)
    java_dirs.sort()
    variables['java_dirs'] = self._Relativize(root_entry, java_dirs)
    variables['java_excludes'] = excludes
    variables['jni_libs'] = self._Relativize(
        root_entry, set(self._GenJniLibs(root_entry)))
    prebuilts = set(
        p for e in self._GetEntries(root_entry) for p in e.PrebuiltJars())
    self.processed_prebuilts.update(prebuilts)
    variables['prebuilts'] = self._Relativize(root_entry, prebuilts)
    res_dirs = set(
        p for e in self._GetEntries(root_entry) for p in e.ResDirs())
    # Do not add generated resources for the all module since it creates many
    # duplicates, and currently resources are only used for editing.
    self.processed_res_dirs.update(res_dirs)
    res_dirs.add(
        os.path.join(self.EntryOutputDir(root_entry), _RES_SUBDIR))
    variables['res_dirs'] = self._Relativize(root_entry, res_dirs)
    android_manifest = root_entry.Gradle().get('android_manifest')
    if not android_manifest:
      android_manifest = self._GenCustomManifest(root_entry)
    variables['android_manifest'] = self._Relativize(
        root_entry, android_manifest)
    if self.split_projects:
      deps = [_ProjectEntry.FromBuildConfigPath(p)
              for p in root_entry.Gradle()['dependent_android_projects']]
      variables['android_project_deps'] = [d.ProjectName() for d in deps]
      deps = [_ProjectEntry.FromBuildConfigPath(p)
              for p in root_entry.Gradle()['dependent_java_projects']]
      variables['java_project_deps'] = [d.ProjectName() for d in deps]
    return variables


def _ComputeJavaSourceDirs(java_files):
  """Returns a dictionary of source dirs with each given files in one."""
  found_roots = {}
  for path in java_files:
    path_root = path
    # Recognize these tokens as top-level.
    while True:
      path_root = os.path.dirname(path_root)
      basename = os.path.basename(path_root)
      assert basename, 'Failed to find source dir for ' + path
      if basename in ('java', 'src'):
        break
      if basename in ('javax', 'org', 'com'):
        path_root = os.path.dirname(path_root)
        break
    if path_root not in found_roots:
      found_roots[path_root] = []
    found_roots[path_root].append(path)
  return found_roots


def _ComputeExcludeFilters(wanted_files, unwanted_files, parent_dir):
  """Returns exclude patters to exclude unwanted files but keep wanted files.

  - Shortens exclude list by globbing if possible.
  - Exclude patterns are relative paths from the parent directory.
  """
  excludes = []
  files_to_include = set(wanted_files)
  files_to_exclude = set(unwanted_files)
  while files_to_exclude:
    unwanted_file = files_to_exclude.pop()
    target_exclude = os.path.join(
        os.path.dirname(unwanted_file), '*.java')
    found_files = set(glob.glob(target_exclude))
    valid_files = found_files & files_to_include
    if valid_files:
      excludes.append(os.path.relpath(unwanted_file, parent_dir))
    else:
      excludes.append(os.path.relpath(target_exclude, parent_dir))
      files_to_exclude -= found_files
  return excludes


def _ComputeJavaSourceDirsAndExcludes(output_dir, java_files):
  """Computes the list of java source directories and exclude patterns.

  1. Computes the root java source directories from the list of files.
  2. Compute exclude patterns that exclude all extra files only.
  3. Returns the list of java source directories and exclude patterns.
  """
  java_dirs = []
  excludes = []
  if java_files:
    java_files = _RebasePath(java_files)
    computed_dirs = _ComputeJavaSourceDirs(java_files)
    java_dirs = computed_dirs.keys()
    all_found_java_files = set()

    for directory, files in computed_dirs.iteritems():
      found_java_files = build_utils.FindInDirectory(directory, '*.java')
      all_found_java_files.update(found_java_files)
      unwanted_java_files = set(found_java_files) - set(files)
      if unwanted_java_files:
        logging.debug('Directory requires excludes: %s', directory)
        excludes.extend(
            _ComputeExcludeFilters(files, unwanted_java_files, directory))

    missing_java_files = set(java_files) - all_found_java_files
    # Warn only about non-generated files that are missing.
    missing_java_files = [p for p in missing_java_files
                          if not p.startswith(output_dir)]
    if missing_java_files:
      logging.warning(
          'Some java files were not found: %s', missing_java_files)

  return java_dirs, excludes


def _CreateRelativeSymlink(target_path, link_path):
  link_dir = os.path.dirname(link_path)
  relpath = os.path.relpath(target_path, link_dir)
  logging.debug('Creating symlink %s -> %s', link_path, relpath)
  os.symlink(relpath, link_path)


def _CreateJniLibsDir(output_dir, entry_output_dir, so_files):
  """Creates directory with symlinked .so files if necessary.

  Returns list of JNI libs directories."""

  if so_files:
    symlink_dir = os.path.join(entry_output_dir, _JNI_LIBS_SUBDIR)
    shutil.rmtree(symlink_dir, True)
    abi_dir = os.path.join(symlink_dir, _ARMEABI_SUBDIR)
    if not os.path.exists(abi_dir):
      os.makedirs(abi_dir)
    for so_file in so_files:
      target_path = os.path.join(output_dir, so_file)
      symlinked_path = os.path.join(abi_dir, so_file)
      _CreateRelativeSymlink(target_path, symlinked_path)

    return [symlink_dir]

  return []


def _GenerateLocalProperties(sdk_dir):
  """Returns the data for project.properties as a string."""
  return '\n'.join([
      '# Generated by //build/android/gradle/generate_gradle.py',
      'sdk.dir=%s' % sdk_dir,
      ''])


def _GenerateBaseVars(generator, build_vars, source_properties):
  variables = {
      'sourceSetName': 'main',
      'depCompileName': 'compile',
  }
  variables['build_tools_version'] = source_properties['Pkg.Revision']
  variables['compile_sdk_version'] = (
      'android-%s' % build_vars['android_sdk_version'])
  variables['use_gradle_process_resources'] = (
      generator.use_gradle_process_resources)
  return variables


def _GenerateGradleFile(entry, generator, build_vars, source_properties,
    jinja_processor):
  """Returns the data for a project's build.gradle."""
  deps_info = entry.DepsInfo()
  gradle = entry.Gradle()

  variables = _GenerateBaseVars(generator, build_vars, source_properties)
  if deps_info['type'] == 'android_apk':
    target_type = 'android_apk'
  elif deps_info['type'] == 'java_library':
    if deps_info['is_prebuilt'] or deps_info['gradle_treat_as_prebuilt']:
      return None
    elif deps_info['requires_android']:
      target_type = 'android_library'
    else:
      target_type = 'java_library'
  elif deps_info['type'] == 'java_binary':
    if gradle['main_class'] == 'org.chromium.testing.local.JunitTestMain':
      target_type = 'android_junit'
      variables['sourceSetName'] = 'test'
      variables['depCompileName'] = 'testCompile'
    else:
      target_type = 'java_binary'
      variables['main_class'] = gradle['main_class']
  else:
    return None

  variables['target_name'] = os.path.splitext(deps_info['name'])[0]
  variables['template_type'] = target_type
  variables['main'] = generator.Generate(entry)
  bootclasspath = gradle.get('bootclasspath')
  if bootclasspath:
    # Must use absolute path here.
    variables['bootclasspath'] = _RebasePath(bootclasspath)
  if entry.android_test_entry:
    variables['android_test'] = generator.Generate(
        entry.android_test_entry)
    for key, value in variables['android_test'].iteritems():
      if isinstance(value, list):
        variables['android_test'][key] = sorted(
            set(value) - set(variables['main'][key]))

  return jinja_processor.Render(
      _TemplatePath(target_type.split('_')[0]), variables)


def _IsTestDir(path):
  return ('javatests/' in path or
          'junit/' in path or
          'test/' in path or
          'testing/' in path)


def _GenerateModuleAll(gradle_output_dir, generator, build_vars,
    source_properties, jinja_processor):
  """Returns the data for a pseudo build.gradle of all dirs.

  See //docs/android_studio.md for more details."""
  variables = _GenerateBaseVars(generator, build_vars, source_properties)
  target_type = 'android_apk'
  variables['target_name'] = _MODULE_ALL
  variables['template_type'] = target_type
  java_dirs = sorted(generator.processed_java_dirs)
  prebuilts = sorted(generator.processed_prebuilts)
  res_dirs = sorted(generator.processed_res_dirs)
  def Relativize(paths):
    return _RebasePath(paths, os.path.join(gradle_output_dir, _MODULE_ALL))
  main_java_dirs = [d for d in java_dirs if not _IsTestDir(d)]
  test_java_dirs = [d for d in java_dirs if _IsTestDir(d)]
  variables['main'] = {
      'android_manifest': Relativize(_DEFAULT_ANDROID_MANIFEST_PATH),
      'java_dirs': Relativize(main_java_dirs),
      'prebuilts': Relativize(prebuilts),
      'java_excludes': ['**/*.java'],
      'res_dirs': Relativize(res_dirs),
  }
  variables['android_test'] = {
      'java_dirs': Relativize(test_java_dirs),
      'java_excludes': ['**/*.java'],
  }
  data = jinja_processor.Render(
      _TemplatePath(target_type.split('_')[0]), variables)
  _WriteFile(
      os.path.join(gradle_output_dir, _MODULE_ALL, _GRADLE_BUILD_FILE), data)


def _GenerateRootGradle(jinja_processor):
  """Returns the data for the root project's build.gradle."""
  return jinja_processor.Render(_TemplatePath('root'))


def _GenerateSettingsGradle(project_entries, add_all_module):
  """Returns the data for settings.gradle."""
  project_name = os.path.basename(os.path.dirname(host_paths.DIR_SOURCE_ROOT))
  lines = []
  lines.append('// Generated by //build/android/gradle/generate_gradle.py')
  lines.append('rootProject.name = "%s"' % project_name)
  lines.append('rootProject.projectDir = settingsDir')
  lines.append('')

  if add_all_module:
    lines.append('include ":{0}"'.format(_MODULE_ALL))
    lines.append(
        'project(":{0}").projectDir = new File(settingsDir, "{0}")'.format(
            _MODULE_ALL))
  for entry in project_entries:
    # Example target: android_webview:android_webview_java__build_config
    lines.append('include ":%s"' % entry.ProjectName())
    lines.append('project(":%s").projectDir = new File(settingsDir, "%s")' %
                 (entry.ProjectName(), entry.GradleSubdir()))
  return '\n'.join(lines)


def _ExtractFile(zip_path, extracted_path):
  logging.info('Extracting %s to %s', zip_path, extracted_path)
  with zipfile.ZipFile(zip_path) as z:
    z.extractall(extracted_path)


def _ExtractZips(entry_output_dir, zip_tuples):
  """Extracts all srcjars to the directory given by the tuples."""
  extracted_paths = set(s[1] for s in zip_tuples)
  for extracted_path in extracted_paths:
    assert _IsSubpathOf(extracted_path, entry_output_dir)
    shutil.rmtree(extracted_path, True)

  for zip_path, extracted_path in zip_tuples:
    _ExtractFile(zip_path, extracted_path)


def _FindAllProjectEntries(main_entries):
  """Returns the list of all _ProjectEntry instances given the root project."""
  found = set()
  to_scan = list(main_entries)
  while to_scan:
    cur_entry = to_scan.pop()
    if cur_entry in found:
      continue
    found.add(cur_entry)
    sub_config_paths = cur_entry.DepsInfo()['deps_configs']
    to_scan.extend(
        _ProjectEntry.FromBuildConfigPath(p) for p in sub_config_paths)
  return list(found)


def _CombineTestEntries(entries):
  """Combines test apks into the androidTest source set of their target.

  - Speeds up android studio
  - Adds proper dependency between test and apk_under_test
  - Doesn't work for junit yet due to resulting circular dependencies
    - e.g. base_junit_tests > base_junit_test_support > base_java
  """
  combined_entries = []
  android_test_entries = {}
  for entry in entries:
    target_name = entry.GnTarget()
    if (target_name.endswith('_test_apk__apk') and
        'apk_under_test' in entry.Gradle()):
      apk_name = entry.Gradle()['apk_under_test']
      android_test_entries[apk_name] = entry
    else:
      combined_entries.append(entry)
  for entry in combined_entries:
    target_name = entry.DepsInfo()['name']
    if target_name in android_test_entries:
      entry.android_test_entry = android_test_entries[target_name]
      del android_test_entries[target_name]
  # Add unmatched test entries as individual targets.
  combined_entries.extend(android_test_entries.values())
  return combined_entries


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--output-directory',
                      help='Path to the root build directory.')
  parser.add_argument('-v',
                      '--verbose',
                      dest='verbose_count',
                      default=0,
                      action='count',
                      help='Verbose level')
  parser.add_argument('--target',
                      dest='targets',
                      action='append',
                      help='GN target to generate project for. Replaces set of '
                           'default targets. May be repeated.')
  parser.add_argument('--extra-target',
                      dest='extra_targets',
                      action='append',
                      help='GN target to generate project for, in addition to '
                           'the default ones. May be repeated.')
  parser.add_argument('--project-dir',
                      help='Root of the output project.',
                      default=os.path.join('$CHROMIUM_OUTPUT_DIR', 'gradle'))
  parser.add_argument('--all',
                      action='store_true',
                      help='Generate all java targets (slows down IDE)')
  parser.add_argument('--use-gradle-process-resources',
                      action='store_true',
                      help='Have gradle generate R.java rather than ninja')
  parser.add_argument('--split-projects',
                      action='store_true',
                      help='Split projects by their gn deps rather than '
                           'combining all the dependencies of each target')
  args = parser.parse_args()
  if args.output_directory:
    constants.SetOutputDirectory(args.output_directory)
  constants.CheckOutputDirectory()
  output_dir = constants.GetOutDirectory()
  devil_chromium.Initialize(output_directory=output_dir)
  run_tests_helper.SetLogLevel(args.verbose_count)

  if args.use_gradle_process_resources:
    assert args.split_projects, (
        'Gradle resources does not work without --split-projects.')

  _gradle_output_dir = os.path.abspath(
      args.project_dir.replace('$CHROMIUM_OUTPUT_DIR', output_dir))
  jinja_processor = jinja_template.JinjaProcessor(_FILE_DIR)
  build_vars = _ReadPropertiesFile(os.path.join(output_dir, 'build_vars.txt'))
  source_properties = _ReadPropertiesFile(
      _RebasePath(os.path.join(build_vars['android_sdk_build_tools'],
                               'source.properties')))
  generator = _ProjectContextGenerator(_gradle_output_dir, build_vars,
      args.use_gradle_process_resources, jinja_processor, args.split_projects)
  logging.warning('Creating project at: %s', generator.project_dir)

  if args.all:
    # Run GN gen if necessary (faster than running "gn gen" in the no-op case).
    _RunNinja(constants.GetOutDirectory(), ['build.ninja'])
    # Query ninja for all __build_config targets.
    targets = _QueryForAllGnTargets(output_dir)
  else:
    targets = args.targets or _DEFAULT_TARGETS
    if args.extra_targets:
      targets.extend(args.extra_targets)
    targets = [re.sub(r'_test_apk$', '_test_apk__apk', t) for t in targets]
    # TODO(wnwen): Utilize Gradle's test constructs for our junit tests?
    targets = [re.sub(r'_junit_tests$', '_junit_tests__java_binary', t)
               for t in targets]

  main_entries = [_ProjectEntry.FromGnTarget(t) for t in targets]

  logging.warning('Building .build_config files...')
  _RunNinja(output_dir, [e.NinjaBuildConfigTarget() for e in main_entries])

  # There are many unused libraries, so restrict to those that are actually used
  # when using --all.
  if args.all:
    main_entries = [e for e in main_entries if (
        e.GetType() == 'android_apk' or
        e.GnTarget().endswith('_test_apk__apk') or
        e.GnTarget().endswith('_junit_tests__java_binary'))]

  if args.split_projects:
    main_entries = _FindAllProjectEntries(main_entries)
    logging.info('Found %d dependent build_config targets.', len(main_entries))

  entries = [e for e in _CombineTestEntries(main_entries) if e.IsValid()]
  logging.info('Creating %d projects for targets.', len(entries))

  # When only one entry will be generated we want it to have a valid
  # build.gradle file with its own AndroidManifest.
  add_all_module = not args.split_projects and len(entries) > 1

  logging.warning('Writing .gradle files...')
  project_entries = []
  zip_tuples = []
  generated_inputs = []
  for entry in entries:
    data = _GenerateGradleFile(entry, generator, build_vars, source_properties,
        jinja_processor)
    if data:
      # Build all paths references by .gradle that exist within output_dir.
      generated_inputs.extend(generator.GeneratedInputs(entry))
      zip_tuples.extend(
          (s, os.path.join(generator.EntryOutputDir(entry), _SRCJARS_SUBDIR))
          for s in generator.AllSrcjars(entry))
      zip_tuples.extend(
          (s, os.path.join(generator.EntryOutputDir(entry), _RES_SUBDIR))
          for s in generator.AllResZips(entry))
      if not add_all_module:
        project_entries.append(entry)
        _WriteFile(
            os.path.join(generator.EntryOutputDir(entry), _GRADLE_BUILD_FILE),
            data)

  if add_all_module:
    _GenerateModuleAll(_gradle_output_dir, generator, build_vars,
        source_properties, jinja_processor)

  _WriteFile(os.path.join(generator.project_dir, _GRADLE_BUILD_FILE),
             _GenerateRootGradle(jinja_processor))

  _WriteFile(os.path.join(generator.project_dir, 'settings.gradle'),
             _GenerateSettingsGradle(project_entries, add_all_module))

  sdk_path = _RebasePath(build_vars['android_sdk_root'])
  _WriteFile(os.path.join(generator.project_dir, 'local.properties'),
             _GenerateLocalProperties(sdk_path))

  if generated_inputs:
    logging.warning('Building generated source files...')
    targets = _RebasePath(generated_inputs, output_dir)
    _RunNinja(output_dir, targets)

  if zip_tuples:
    _ExtractZips(generator.project_dir, zip_tuples)

  logging.warning('Project created!')
  logging.warning('Generated projects work with Android Studio 2.3')
  logging.warning('For more tips: https://chromium.googlesource.com/chromium'
                  '/src.git/+/master/docs/android_studio.md')


if __name__ == '__main__':
  main()

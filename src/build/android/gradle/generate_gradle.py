#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Generates an Android Studio project from a GN target."""

import argparse
import codecs
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
_JAVA_SUBDIR = 'symlinked-java'
_SRCJARS_SUBDIR = 'extracted-srcjars'
_JNI_LIBS_SUBDIR = 'symlinked-libs'
_ARMEABI_SUBDIR = 'armeabi'

_DEFAULT_TARGETS = [
    # TODO(agrieve): Requires alternate android.jar to compile.
    # '//android_webview:system_webview_apk',
    '//android_webview/test:android_webview_apk',
    '//android_webview/test:android_webview_test_apk',
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


def _ReadBuildVars(output_dir):
  with open(os.path.join(output_dir, 'build_vars.txt')) as f:
    return dict(l.rstrip().split('=', 1) for l in f)


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
  def __init__(self, gn_target):
    assert gn_target.startswith('//'), gn_target
    if ':' not in gn_target:
      gn_target = '%s:%s' % (gn_target, os.path.basename(gn_target))
    self._gn_target = gn_target
    self._build_config = None
    self._java_files = None
    self.android_test_entry = None

  @classmethod
  def FromBuildConfigPath(cls, path):
    prefix = 'gen/'
    suffix = '.build_config'
    assert path.startswith(prefix) and path.endswith(suffix), path
    subdir = path[len(prefix):-len(suffix)]
    return cls('//%s:%s' % (os.path.split(subdir)))

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

  def GetType(self):
    """Returns the target type from its .build_config."""
    return self.DepsInfo()['type']

  def JavaFiles(self):
    if self._java_files is None:
      java_sources_file = self.Gradle().get('java_sources_file')
      java_files = []
      if java_sources_file:
        java_sources_file = _RebasePath(java_sources_file)
        java_files = build_utils.ReadSourcesList(java_sources_file)
      self._java_files = java_files
    return self._java_files


class _ProjectContextGenerator(object):
  """Helper class to generate gradle build files"""
  def __init__(self, project_dir, use_gradle_process_resources):
    self.project_dir = project_dir
    self.use_gradle_process_resources = use_gradle_process_resources

  def _GenJniLibs(self, entry):
    native_section = entry.BuildConfig().get('native')
    if native_section:
      jni_libs = _CreateJniLibsDir(
          constants.GetOutDirectory(), self.EntryOutputDir(entry),
          native_section.get('libraries'))
    else:
      jni_libs = []
    return jni_libs

  def _GenJavaDirs(self, entry):
    java_dirs = _CreateJavaSourceDir(
        constants.GetOutDirectory(), self.EntryOutputDir(entry),
        entry.JavaFiles())
    if self.Srcjars(entry):
      java_dirs.append(
          os.path.join(self.EntryOutputDir(entry), _SRCJARS_SUBDIR))
    return java_dirs

  def _Relativize(self, entry, paths):
    return _RebasePath(paths, self.EntryOutputDir(entry))

  def EntryOutputDir(self, entry):
    return os.path.join(self.project_dir, entry.GradleSubdir())

  def Srcjars(self, entry):
    srcjars = _RebasePath(entry.Gradle().get('bundled_srcjars', []))
    if not self.use_gradle_process_resources:
      srcjars += _RebasePath(entry.BuildConfig()['javac']['srcjars'])
    return srcjars

  def GeneratedInputs(self, entry):
    generated_inputs = []
    generated_inputs.extend(self.Srcjars(entry))
    generated_inputs.extend(
        p for p in entry.JavaFiles() if not p.startswith('..'))
    generated_inputs.extend(entry.Gradle()['dependent_prebuilt_jars'])
    return generated_inputs

  def Generate(self, entry):
    variables = {}
    android_test_manifest = entry.Gradle().get(
        'android_manifest', _DEFAULT_ANDROID_MANIFEST_PATH)
    variables['android_manifest'] = self._Relativize(
        entry, android_test_manifest)
    variables['java_dirs'] = self._Relativize(entry, self._GenJavaDirs(entry))
    variables['jni_libs'] = self._Relativize(entry, self._GenJniLibs(entry))
    deps = [_ProjectEntry.FromBuildConfigPath(p)
            for p in entry.Gradle()['dependent_android_projects']]
    variables['android_project_deps'] = [d.ProjectName() for d in deps]
    # TODO(agrieve): Add an option to use interface jars and see if that speeds
    # things up at all.
    variables['prebuilts'] = self._Relativize(
        entry, entry.Gradle()['dependent_prebuilt_jars'])
    deps = [_ProjectEntry.FromBuildConfigPath(p)
            for p in entry.Gradle()['dependent_java_projects']]
    variables['java_project_deps'] = [d.ProjectName() for d in deps]
    return variables


def _ComputeJavaSourceDirs(java_files):
  """Returns the list of source directories for the given files."""
  found_roots = set()
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
    found_roots.add(path_root)
  return list(found_roots)


def _CreateRelativeSymlink(target_path, link_path):
  link_dir = os.path.dirname(link_path)
  relpath = os.path.relpath(target_path, link_dir)
  logging.debug('Creating symlink %s -> %s', link_path, relpath)
  os.symlink(relpath, link_path)


def _CreateSymlinkTree(entry_output_dir, symlink_dir, desired_files,
                       parent_dirs):
  """Creates a directory tree of symlinks to the given files.

  The idea here is to replicate a directory tree while leaving out files within
  it not listed by |desired_files|.
  """
  assert _IsSubpathOf(symlink_dir, entry_output_dir)

  for target_path in desired_files:
    prefix = next(d for d in parent_dirs if target_path.startswith(d))
    subpath = os.path.relpath(target_path, prefix)
    symlinked_path = os.path.join(symlink_dir, subpath)
    symlinked_dir = os.path.dirname(symlinked_path)
    if not os.path.exists(symlinked_dir):
      os.makedirs(symlinked_dir)
    _CreateRelativeSymlink(target_path, symlinked_path)


def _CreateJavaSourceDir(output_dir, entry_output_dir, java_files):
  """Computes and constructs when necessary the list of java source directories.

  1. Computes the root java source directories from the list of files.
  2. Determines whether there are any .java files in them that are not included
     in |java_files|.
  3. If not, returns the list of java source directories. If so, constructs a
     tree of symlinks within |entry_output_dir| of all files in |java_files|.
  """
  java_dirs = []
  if java_files:
    java_files = _RebasePath(java_files)
    java_dirs = _ComputeJavaSourceDirs(java_files)

    found_java_files = build_utils.FindInDirectories(java_dirs, '*.java')
    unwanted_java_files = set(found_java_files) - set(java_files)
    missing_java_files = set(java_files) - set(found_java_files)
    # Warn only about non-generated files that are missing.
    missing_java_files = [p for p in missing_java_files
                          if not p.startswith(output_dir)]

    symlink_dir = os.path.join(entry_output_dir, _JAVA_SUBDIR)
    shutil.rmtree(symlink_dir, True)

    if unwanted_java_files:
      logging.debug('Target requires .java symlinks: %s', entry_output_dir)
      _CreateSymlinkTree(entry_output_dir, symlink_dir, java_files, java_dirs)
      java_dirs = [symlink_dir]

    if missing_java_files:
      logging.warning('Some java files were not found: %s', missing_java_files)

  return java_dirs


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


def _GenerateGradleFile(entry, generator, build_vars, jinja_processor):
  """Returns the data for a project's build.gradle."""
  deps_info = entry.DepsInfo()
  gradle = entry.Gradle()

  variables = {
      'sourceSetName': 'main',
      'depCompileName': 'compile',
  }
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
  variables['use_gradle_process_resources'] = (
      generator.use_gradle_process_resources)
  variables['build_tools_version'] = (
      build_vars['android_sdk_build_tools_version'])
  variables['compile_sdk_version'] = build_vars['android_sdk_version']
  variables['main'] = generator.Generate(entry)
  if entry.android_test_entry:
    variables['android_test'] = generator.Generate(
        entry.android_test_entry)

  return jinja_processor.Render(
      _TemplatePath(target_type.split('_')[0]), variables)


def _GenerateRootGradle(jinja_processor):
  """Returns the data for the root project's build.gradle."""
  return jinja_processor.Render(_TemplatePath('root'))


def _GenerateSettingsGradle(project_entries):
  """Returns the data for settings.gradle."""
  project_name = os.path.basename(os.path.dirname(host_paths.DIR_SOURCE_ROOT))
  lines = []
  lines.append('// Generated by //build/android/gradle/generate_gradle.py')
  lines.append('rootProject.name = "%s"' % project_name)
  lines.append('rootProject.projectDir = settingsDir')
  lines.append('')

  for entry in project_entries:
    # Example target: android_webview:android_webview_java__build_config
    lines.append('include ":%s"' % entry.ProjectName())
    lines.append('project(":%s").projectDir = new File(settingsDir, "%s")' %
                 (entry.ProjectName(), entry.GradleSubdir()))
  return '\n'.join(lines)


def _ExtractSrcjars(entry_output_dir, srcjar_tuples):
  """Extracts all srcjars to the directory given by the tuples."""
  extracted_paths = set(s[1] for s in srcjar_tuples)
  for extracted_path in extracted_paths:
    assert _IsSubpathOf(extracted_path, entry_output_dir)
    shutil.rmtree(extracted_path, True)

  for srcjar_path, extracted_path in srcjar_tuples:
    logging.info('Extracting %s to %s', srcjar_path, extracted_path)
    with zipfile.ZipFile(srcjar_path) as z:
      z.extractall(extracted_path)


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
                      help='GN target to generate project for. '
                           'May be repeated.')
  parser.add_argument('--project-dir',
                      help='Root of the output project.',
                      default=os.path.join('$CHROMIUM_OUTPUT_DIR', 'gradle'))
  parser.add_argument('--all',
                      action='store_true',
                      help='Generate all java targets (slows down IDE)')
  parser.add_argument('--use-gradle-process-resources',
                      action='store_true',
                      help='Have gradle generate R.java rather than ninja')
  args = parser.parse_args()
  if args.output_directory:
    constants.SetOutputDirectory(args.output_directory)
  constants.CheckOutputDirectory()
  output_dir = constants.GetOutDirectory()
  devil_chromium.Initialize(output_directory=output_dir)
  run_tests_helper.SetLogLevel(args.verbose_count)

  _gradle_output_dir = os.path.abspath(
      args.project_dir.replace('$CHROMIUM_OUTPUT_DIR', output_dir))
  generator = _ProjectContextGenerator(
      _gradle_output_dir, args.use_gradle_process_resources)
  logging.warning('Creating project at: %s', generator.project_dir)

  if args.all:
    # Run GN gen if necessary (faster than running "gn gen" in the no-op case).
    _RunNinja(constants.GetOutDirectory(), ['build.ninja'])
    # Query ninja for all __build_config targets.
    targets = _QueryForAllGnTargets(output_dir)
  else:
    targets = args.targets or _DEFAULT_TARGETS
    targets = [re.sub(r'_test_apk$', '_test_apk__apk', t) for t in targets]
    # TODO(wnwen): Utilize Gradle's test constructs for our junit tests?
    targets = [re.sub(r'_junit_tests$', '_junit_tests__java_binary', t)
               for t in targets]

  main_entries = [_ProjectEntry(t) for t in targets]

  logging.warning('Building .build_config files...')
  _RunNinja(output_dir, [e.NinjaBuildConfigTarget() for e in main_entries])

  # There are many unused libraries, so restrict to those that are actually used
  # when using --all.
  if args.all:
    main_entries = [e for e in main_entries if e.GetType() == 'android_apk']

  all_entries = _FindAllProjectEntries(main_entries)
  logging.info('Found %d dependent build_config targets.', len(all_entries))
  entries = _CombineTestEntries(all_entries)
  logging.info('Creating %d projects for targets.', len(entries))

  logging.warning('Writing .gradle files...')
  jinja_processor = jinja_template.JinjaProcessor(_FILE_DIR)
  build_vars = _ReadBuildVars(output_dir)
  project_entries = []
  srcjar_tuples = []
  generated_inputs = []
  for entry in entries:
    if entry.GetType() not in ('android_apk', 'java_library', 'java_binary'):
      continue

    data = _GenerateGradleFile(entry, generator, build_vars, jinja_processor)
    if data:
      project_entries.append(entry)
      # Build all paths references by .gradle that exist within output_dir.
      generated_inputs.extend(generator.GeneratedInputs(entry))
      srcjar_tuples.extend(
          (s, os.path.join(generator.EntryOutputDir(entry), _SRCJARS_SUBDIR))
          for s in generator.Srcjars(entry))
      _WriteFile(
          os.path.join(generator.EntryOutputDir(entry), 'build.gradle'), data)

  _WriteFile(os.path.join(generator.project_dir, 'build.gradle'),
             _GenerateRootGradle(jinja_processor))

  _WriteFile(os.path.join(generator.project_dir, 'settings.gradle'),
             _GenerateSettingsGradle(project_entries))

  sdk_path = _RebasePath(build_vars['android_sdk_root'])
  _WriteFile(os.path.join(generator.project_dir, 'local.properties'),
             _GenerateLocalProperties(sdk_path))

  if generated_inputs:
    logging.warning('Building generated source files...')
    targets = _RebasePath(generated_inputs, output_dir)
    _RunNinja(output_dir, targets)

  if srcjar_tuples:
    _ExtractSrcjars(generator.project_dir, srcjar_tuples)

  logging.warning('Project created! (%d subprojects)', len(project_entries))
  logging.warning('Generated projects work best with Android Studio 2.2')
  logging.warning('For more tips: https://chromium.googlesource.com/chromium'
                  '/src.git/+/master/docs/android_studio.md')


if __name__ == '__main__':
  main()

#!/usr/bin/env python
#
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=C0301
"""Package resources into an apk.

See https://android.googlesource.com/platform/tools/base/+/master/legacy/ant-tasks/src/main/java/com/android/ant/AaptExecTask.java
and
https://android.googlesource.com/platform/sdk/+/master/files/ant/build.xml
"""
# pylint: enable=C0301

import optparse
import os
import re
import shutil
import sys
import zipfile

from util import build_utils


# A variation of this lists also exists in:
# //base/android/java/src/org/chromium/base/LocaleUtils.java
_CHROME_TO_ANDROID_LOCALE_MAP = {
    'en-GB': 'en-rGB',
    'en-US': 'en-rUS',
    'es-419': 'es-rUS',
    'fin': 'tl',
    'he': 'iw',
    'id': 'in',
    'pt-PT': 'pt-rPT',
    'pt-BR': 'pt-rBR',
    'yi': 'ji',
    'zh-CN': 'zh-rCN',
    'zh-TW': 'zh-rTW',
}

# List is generated from the chrome_apk.apk_intermediates.ap_ via:
#     unzip -l $FILE_AP_ | cut -c31- | grep res/draw | cut -d'/' -f 2 | sort \
#     | uniq | grep -- -tvdpi- | cut -c10-
# and then manually sorted.
# Note that we can't just do a cross-product of dimentions because the filenames
# become too big and aapt fails to create the files.
# This leaves all default drawables (mdpi) in the main apk. Android gets upset
# though if any drawables are missing from the default drawables/ directory.
DENSITY_SPLITS = {
    'hdpi': (
        'hdpi-v4', # Order matters for output file names.
        'ldrtl-hdpi-v4',
        'sw600dp-hdpi-v13',
        'ldrtl-hdpi-v17',
        'ldrtl-sw600dp-hdpi-v17',
        'hdpi-v21',
    ),
    'xhdpi': (
        'xhdpi-v4',
        'ldrtl-xhdpi-v4',
        'sw600dp-xhdpi-v13',
        'ldrtl-xhdpi-v17',
        'ldrtl-sw600dp-xhdpi-v17',
        'xhdpi-v21',
    ),
    'xxhdpi': (
        'xxhdpi-v4',
        'ldrtl-xxhdpi-v4',
        'sw600dp-xxhdpi-v13',
        'ldrtl-xxhdpi-v17',
        'ldrtl-sw600dp-xxhdpi-v17',
        'xxhdpi-v21',
    ),
    'xxxhdpi': (
        'xxxhdpi-v4',
        'ldrtl-xxxhdpi-v4',
        'sw600dp-xxxhdpi-v13',
        'ldrtl-xxxhdpi-v17',
        'ldrtl-sw600dp-xxxhdpi-v17',
        'xxxhdpi-v21',
    ),
    'tvdpi': (
        'tvdpi-v4',
        'sw600dp-tvdpi-v13',
        'ldrtl-sw600dp-tvdpi-v17',
    ),
}


def _ParseArgs(args):
  """Parses command line options.

  Returns:
    An options object as from optparse.OptionsParser.parse_args()
  """
  parser = optparse.OptionParser()
  build_utils.AddDepfileOption(parser)
  parser.add_option('--android-sdk-jar',
                    help='path to the Android SDK jar.')
  parser.add_option('--aapt-path',
                    help='path to the Android aapt tool')

  parser.add_option('--configuration-name',
                    help='Gyp\'s configuration name (Debug or Release).')

  parser.add_option('--android-manifest', help='AndroidManifest.xml path')
  parser.add_option('--version-code', help='Version code for apk.')
  parser.add_option('--version-name', help='Version name for apk.')
  parser.add_option(
      '--shared-resources',
      action='store_true',
      help='Make a resource package that can be loaded by a different'
      'application at runtime to access the package\'s resources.')
  parser.add_option(
      '--app-as-shared-lib',
      action='store_true',
      help='Make a resource package that can be loaded as shared library')
  parser.add_option('--resource-zips',
                    default='[]',
                    help='zip files containing resources to be packaged')
  parser.add_option('--asset-dir',
                    help='directories containing assets to be packaged')
  parser.add_option('--no-compress', help='disables compression for the '
                    'given comma separated list of extensions')
  parser.add_option(
      '--create-density-splits',
      action='store_true',
      help='Enables density splits')
  parser.add_option('--language-splits',
                    default='[]',
                    help='GN list of languages to create splits for')
  parser.add_option('--locale-whitelist',
                    default='[]',
                    help='GN list of languages to include. All other language '
                         'configs will be stripped out. List may include '
                         'a combination of Android locales or Chrome locales.')

  parser.add_option('--apk-path',
                    help='Path to output (partial) apk.')

  options, positional_args = parser.parse_args(args)

  if positional_args:
    parser.error('No positional arguments should be given.')

  # Check that required options have been provided.
  required_options = ('android_sdk_jar', 'aapt_path', 'configuration_name',
                      'android_manifest', 'version_code', 'version_name',
                      'apk_path')

  build_utils.CheckOptions(options, parser, required=required_options)

  options.resource_zips = build_utils.ParseGnList(options.resource_zips)
  options.language_splits = build_utils.ParseGnList(options.language_splits)
  options.locale_whitelist = build_utils.ParseGnList(options.locale_whitelist)
  return options


def _ToAaptLocales(locale_whitelist):
  """Converts the list of Chrome locales to aapt config locales."""
  ret = set()
  for locale in locale_whitelist:
    locale = _CHROME_TO_ANDROID_LOCALE_MAP.get(locale, locale)
    if locale is None or ('-' in locale and '-r' not in locale):
      raise Exception('_CHROME_TO_ANDROID_LOCALE_MAP needs updating.'
                      ' Found: %s' % locale)
    ret.add(locale)
    # Always keep non-regional fall-backs.
    language = locale.split('-')[0]
    ret.add(language)

  return sorted(ret)


def MoveImagesToNonMdpiFolders(res_root):
  """Move images from drawable-*-mdpi-* folders to drawable-* folders.

  Why? http://crbug.com/289843
  """
  for src_dir_name in os.listdir(res_root):
    src_components = src_dir_name.split('-')
    if src_components[0] != 'drawable' or 'mdpi' not in src_components:
      continue
    src_dir = os.path.join(res_root, src_dir_name)
    if not os.path.isdir(src_dir):
      continue
    dst_components = [c for c in src_components if c != 'mdpi']
    assert dst_components != src_components
    dst_dir_name = '-'.join(dst_components)
    dst_dir = os.path.join(res_root, dst_dir_name)
    build_utils.MakeDirectory(dst_dir)
    for src_file_name in os.listdir(src_dir):
      if not src_file_name.endswith('.png'):
        continue
      src_file = os.path.join(src_dir, src_file_name)
      dst_file = os.path.join(dst_dir, src_file_name)
      assert not os.path.lexists(dst_file)
      shutil.move(src_file, dst_file)


def PackageArgsForExtractedZip(d):
  """Returns the aapt args for an extracted resources zip.

  A resources zip either contains the resources for a single target or for
  multiple targets. If it is multiple targets merged into one, the actual
  resource directories will be contained in the subdirectories 0, 1, 2, ...
  """
  subdirs = [os.path.join(d, s) for s in os.listdir(d)]
  subdirs = [s for s in subdirs if os.path.isdir(s)]
  is_multi = '0' in [os.path.basename(s) for s in subdirs]
  if is_multi:
    res_dirs = sorted(subdirs, key=lambda p : int(os.path.basename(p)))
  else:
    res_dirs = [d]
  package_command = []
  for d in res_dirs:
    MoveImagesToNonMdpiFolders(d)
    package_command += ['-S', d]
  return package_command


def _GenerateDensitySplitPaths(apk_path):
  for density, config in DENSITY_SPLITS.iteritems():
    src_path = '%s_%s' % (apk_path, '_'.join(config))
    dst_path = '%s_%s' % (apk_path, density)
    yield src_path, dst_path


def _GenerateLanguageSplitOutputPaths(apk_path, languages):
  for lang in languages:
    yield '%s_%s' % (apk_path, lang)


def RenameDensitySplits(apk_path):
  """Renames all density splits to have shorter / predictable names."""
  for src_path, dst_path in _GenerateDensitySplitPaths(apk_path):
    shutil.move(src_path, dst_path)


def CheckForMissedConfigs(apk_path, check_density, languages):
  """Raises an exception if apk_path contains any unexpected configs."""
  triggers = []
  if check_density:
    triggers.extend(re.compile('-%s' % density) for density in DENSITY_SPLITS)
  if languages:
    triggers.extend(re.compile(r'-%s\b' % lang) for lang in languages)
  with zipfile.ZipFile(apk_path) as main_apk_zip:
    for name in main_apk_zip.namelist():
      for trigger in triggers:
        if trigger.search(name) and not 'mipmap-' in name:
          raise Exception(('Found config in main apk that should have been ' +
                           'put into a split: %s\nYou need to update ' +
                           'package_resources.py to include this new ' +
                           'config (trigger=%s)') % (name, trigger.pattern))


def _ConstructMostAaptArgs(options):
  package_command = [
      options.aapt_path,
      'package',
      '--version-code', options.version_code,
      '--version-name', options.version_name,
      '-M', options.android_manifest,
      '--no-crunch',
      '-f',
      '--auto-add-overlay',
      '--no-version-vectors',
      '-I', options.android_sdk_jar,
      '-F', options.apk_path,
      '--ignore-assets', build_utils.AAPT_IGNORE_PATTERN,
  ]

  if options.no_compress:
    for ext in options.no_compress.split(','):
      package_command += ['-0', ext]

  if options.shared_resources:
    package_command.append('--shared-lib')

  if options.app_as_shared_lib:
    package_command.append('--app-as-shared-lib')

  if options.asset_dir and os.path.exists(options.asset_dir):
    package_command += ['-A', options.asset_dir]

  if options.create_density_splits:
    for config in DENSITY_SPLITS.itervalues():
      package_command.extend(('--split', ','.join(config)))

  if options.language_splits:
    for lang in options.language_splits:
      package_command.extend(('--split', lang))

  if 'Debug' in options.configuration_name:
    package_command += ['--debug-mode']

  if options.locale_whitelist:
    aapt_locales = _ToAaptLocales(options.locale_whitelist)
    package_command += ['-c', ','.join(aapt_locales)]

  return package_command


def _OnStaleMd5(package_command, options):
  with build_utils.TempDir() as temp_dir:
    if options.resource_zips:
      dep_zips = options.resource_zips
      for z in dep_zips:
        subdir = os.path.join(temp_dir, os.path.basename(z))
        if os.path.exists(subdir):
          raise Exception('Resource zip name conflict: ' + os.path.basename(z))
        build_utils.ExtractAll(z, path=subdir)
        package_command += PackageArgsForExtractedZip(subdir)

    build_utils.CheckOutput(
        package_command, print_stdout=False, print_stderr=False)

    if options.create_density_splits or options.language_splits:
      CheckForMissedConfigs(options.apk_path, options.create_density_splits,
                            options.language_splits)

    if options.create_density_splits:
      RenameDensitySplits(options.apk_path)


def main(args):
  args = build_utils.ExpandFileArgs(args)
  options = _ParseArgs(args)

  package_command = _ConstructMostAaptArgs(options)

  output_paths = [ options.apk_path ]

  if options.create_density_splits:
    for _, dst_path in _GenerateDensitySplitPaths(options.apk_path):
      output_paths.append(dst_path)
  output_paths.extend(
      _GenerateLanguageSplitOutputPaths(options.apk_path,
                                        options.language_splits))

  input_paths = [ options.android_manifest ] + options.resource_zips

  input_strings = []
  input_strings.extend(package_command)

  # The md5_check.py doesn't count file path in md5 intentionally,
  # in order to repackage resources when assets' name changed, we need
  # to put assets into input_strings, as we know the assets path isn't
  # changed among each build if there is no asset change.
  if options.asset_dir and os.path.exists(options.asset_dir):
    asset_paths = []
    for root, _, filenames in os.walk(options.asset_dir):
      asset_paths.extend(os.path.join(root, f) for f in filenames)
    input_paths.extend(asset_paths)
    input_strings.extend(sorted(asset_paths))

  build_utils.CallAndWriteDepfileIfStale(
      lambda: _OnStaleMd5(package_command, options),
      options,
      input_paths=input_paths,
      input_strings=input_strings,
      output_paths=output_paths)


if __name__ == '__main__':
  main(sys.argv[1:])

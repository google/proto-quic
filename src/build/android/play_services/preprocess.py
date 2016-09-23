#!/usr/bin/env python
#
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Prepares the Google Play services split client libraries before usage by
Chrome's build system.

We need to preprocess Google Play services before using it in Chrome
builds for 2 main reasons:

- Getting rid of unused resources: unsupported languages, unused
drawables, etc.

- Merging the differents jars so that it can be proguarded more
easily. This is necessary since debug and test apks get very close
to the dex limit.

The script is supposed to be used with the maven repository that can be
obtained by downloading the "extra-google-m2repository" from the Android SDK
Manager. It also supports importing from already extracted AAR files using the
--is-extracted-repo flag. The expected directory structure in that case would
look like:

    REPOSITORY_DIR
    +-- CLIENT_1
    |   +-- <content of the first AAR file>
    +-- CLIENT_2
    +-- etc.

The output is a directory with the following structure:

    OUT_DIR
    +-- google-play-services.jar
    +-- res
    |   +-- CLIENT_1
    |   |   +-- color
    |   |   +-- values
    |   |   +-- etc.
    |   +-- CLIENT_2
    |       +-- ...
    +-- stub
        +-- res/[.git-keep-directory]
        +-- src/android/UnusedStub.java

Requires the `jar` utility in the path.

'''

import argparse
import glob
import itertools
import os
import shutil
import stat
import sys
import tempfile
import zipfile

from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
import devil_chromium
from devil.utils import cmd_helper
from play_services import utils
from pylib.utils import argparse_utils


def main():
  parser = argparse.ArgumentParser(description=(
      "Prepares the Google Play services split client libraries before usage "
      "by Chrome's build system. See the script's documentation for more a "
      "detailed help."))
  argparse_utils.CustomHelpAction.EnableFor(parser)
  required_args = parser.add_argument_group('required named arguments')
  required_args.add_argument('-r',
                             '--repository',
                             help=('the Google Play services repository '
                                   'location'),
                             required=True,
                             metavar='FILE')
  required_args.add_argument('-o',
                             '--out-dir',
                             help='the output directory',
                             required=True,
                             metavar='FILE')
  required_args.add_argument('-c',
                             '--config-file',
                             help='the config file path',
                             required=True,
                             metavar='FILE')
  parser.add_argument('-x',
                      '--is-extracted-repo',
                      action='store_true',
                      help='the provided repository is not made of AAR files')
  parser.add_argument('--config-help',
                      action='custom_help',
                      custom_help_text=utils.ConfigParser.__doc__,
                      help='show the configuration file format help')

  args = parser.parse_args()

  devil_chromium.Initialize()

  return ProcessGooglePlayServices(args.repository,
                                   args.out_dir,
                                   args.config_file,
                                   args.is_extracted_repo)


def ProcessGooglePlayServices(repo, out_dir, config_path, is_extracted_repo):
  config = utils.ConfigParser(config_path)

  tmp_root = tempfile.mkdtemp()
  try:
    tmp_paths = _SetupTempDir(tmp_root)

    if is_extracted_repo:
      _ImportFromExtractedRepo(config, tmp_paths, repo)
    else:
      _ImportFromAars(config, tmp_paths, repo)

    _GenerateCombinedJar(tmp_paths)
    _ProcessResources(config, tmp_paths, repo)
    _BuildOutput(config, tmp_paths, out_dir)
  finally:
    shutil.rmtree(tmp_root)

  return 0


def _SetupTempDir(tmp_root):
  tmp_paths = {
      'root': tmp_root,
      'imported_clients': os.path.join(tmp_root, 'imported_clients'),
      'extracted_jars': os.path.join(tmp_root, 'jar'),
      'combined_jar': os.path.join(tmp_root, 'google-play-services.jar'),
  }
  os.mkdir(tmp_paths['imported_clients'])
  os.mkdir(tmp_paths['extracted_jars'])

  return tmp_paths


def _SetupOutputDir(out_dir):
  out_paths = {
      'root': out_dir,
      'res': os.path.join(out_dir, 'res'),
      'jar': os.path.join(out_dir, 'google-play-services.jar'),
      'stub': os.path.join(out_dir, 'stub'),
  }

  shutil.rmtree(out_paths['jar'], ignore_errors=True)
  shutil.rmtree(out_paths['res'], ignore_errors=True)
  shutil.rmtree(out_paths['stub'], ignore_errors=True)

  return out_paths


def _MakeWritable(dir_path):
  for root, dirs, files in os.walk(dir_path):
    for path in itertools.chain(dirs, files):
      st = os.stat(os.path.join(root, path))
      os.chmod(os.path.join(root, path), st.st_mode | stat.S_IWUSR)


# E.g. turn "base_1p" into "base"
def _RemovePartySuffix(client):
  return client[:-3] if client[-3:] == '_1p' else client


def _ImportFromAars(config, tmp_paths, repo):
  for client in config.clients:
    client_name = _RemovePartySuffix(client)
    aar_name = 'client_' + client + '.aar'
    aar_path = os.path.join(repo, client_name, aar_name)
    aar_out_path = os.path.join(tmp_paths['imported_clients'], client)
    _ExtractAll(aar_path, aar_out_path)

    client_jar_path = os.path.join(aar_out_path, 'classes.jar')
    _ExtractAll(client_jar_path, tmp_paths['extracted_jars'])


def _ImportFromExtractedRepo(config, tmp_paths, repo):
  # Import the clients
  try:
    for client in config.clients:
      client_out_dir = os.path.join(tmp_paths['imported_clients'], client)
      shutil.copytree(os.path.join(repo, client), client_out_dir)

      client_jar_path = os.path.join(client_out_dir, 'classes.jar')
      _ExtractAll(client_jar_path, tmp_paths['extracted_jars'])
  finally:
    _MakeWritable(tmp_paths['imported_clients'])


def _GenerateCombinedJar(tmp_paths):
  out_file_name = tmp_paths['combined_jar']
  working_dir = tmp_paths['extracted_jars']
  cmd_helper.Call(['jar', '-cf', out_file_name, '-C', working_dir, '.'])


def _ProcessResources(config, tmp_paths, repo):
  LOCALIZED_VALUES_BASE_NAME = 'values-'
  locale_whitelist = set(config.locale_whitelist)

  # The directory structure here is:
  # <imported_clients temp dir>/<client name>_1p/res/<res type>/<res file>.xml
  for client_dir in os.listdir(tmp_paths['imported_clients']):
    client_prefix = _RemovePartySuffix(client_dir) + '_'

    res_path = os.path.join(tmp_paths['imported_clients'], client_dir, 'res')
    if not os.path.isdir(res_path):
      continue
    for res_type in os.listdir(res_path):
      res_type_path = os.path.join(res_path, res_type)

      if res_type.startswith('drawable'):
        shutil.rmtree(res_type_path)
        continue

      if res_type.startswith(LOCALIZED_VALUES_BASE_NAME):
        dir_locale = res_type[len(LOCALIZED_VALUES_BASE_NAME):]
        if dir_locale not in locale_whitelist:
          shutil.rmtree(res_type_path)
          continue

      if res_type.startswith('values'):
        # Beginning with v3, resource file names are not necessarily unique, and
        # would overwrite each other when merged at build time. Prefix each
        # "values" resource file with its client name.
        for res_file in os.listdir(res_type_path):
          os.rename(os.path.join(res_type_path, res_file),
                    os.path.join(res_type_path, client_prefix + res_file))

  # Reimport files from the whitelist.
  for res_path in config.resource_whitelist:
    for whitelisted_file in glob.glob(os.path.join(repo, res_path)):
      resolved_file = os.path.relpath(whitelisted_file, repo)
      rebased_res = os.path.join(tmp_paths['imported_clients'], resolved_file)

      if not os.path.exists(os.path.dirname(rebased_res)):
        os.makedirs(os.path.dirname(rebased_res))

      shutil.copy(os.path.join(repo, whitelisted_file), rebased_res)


def _BuildOutput(config, tmp_paths, out_dir):
  generation_date = datetime.utcnow()
  version_xml_path = os.path.join(tmp_paths['imported_clients'],
                                  config.version_xml_path)
  play_services_full_version = utils.GetVersionNumberFromLibraryResources(
      version_xml_path)

  out_paths = _SetupOutputDir(out_dir)

  # Copy the resources to the output dir
  for client in config.clients:
    res_in_tmp_dir = os.path.join(tmp_paths['imported_clients'], client, 'res')
    if os.path.isdir(res_in_tmp_dir) and os.listdir(res_in_tmp_dir):
      res_in_final_dir = os.path.join(out_paths['res'], client)
      shutil.copytree(res_in_tmp_dir, res_in_final_dir)

  # Copy the jar
  shutil.copyfile(tmp_paths['combined_jar'], out_paths['jar'])

  # Write the java dummy stub. Needed for gyp to create the resource jar
  stub_location = os.path.join(out_paths['stub'], 'src', 'android')
  os.makedirs(stub_location)
  with open(os.path.join(stub_location, 'UnusedStub.java'), 'w') as stub:
    stub.write('package android;'
               'public final class UnusedStub {'
               '    private UnusedStub() {}'
               '}')

  # Create the main res directory. It is needed by gyp
  stub_res_location = os.path.join(out_paths['stub'], 'res')
  os.makedirs(stub_res_location)
  with open(os.path.join(stub_res_location, '.res-stamp'), 'w') as stamp:
    content_str = 'google_play_services_version: %s\nutc_date: %s\n'
    stamp.write(content_str % (play_services_full_version, generation_date))

  config.UpdateVersionNumber(play_services_full_version)


def _ExtractAll(zip_path, out_path):
  with zipfile.ZipFile(zip_path, 'r') as zip_file:
    zip_file.extractall(out_path)

if __name__ == '__main__':
  sys.exit(main())

#!/usr/bin/env python
#
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Adds the code parts to a resource APK."""

import argparse
import itertools
import os
import shutil
import sys
import zipfile

from util import build_utils


# Taken from aapt's Package.cpp:
_NO_COMPRESS_EXTENSIONS = ('.jpg', '.jpeg', '.png', '.gif', '.wav', '.mp2',
                           '.mp3', '.ogg', '.aac', '.mpg', '.mpeg', '.mid',
                           '.midi', '.smf', '.jet', '.rtttl', '.imy', '.xmf',
                           '.mp4', '.m4a', '.m4v', '.3gp', '.3gpp', '.3g2',
                           '.3gpp2', '.amr', '.awb', '.wma', '.wmv', '.webm')


def _ParseArgs(args):
  parser = argparse.ArgumentParser()
  build_utils.AddDepfileOption(parser)
  parser.add_argument('--assets',
                      help='GYP-list of files to add as assets in the form '
                           '"srcPath:zipPath", where ":zipPath" is optional.',
                      default='[]')
  parser.add_argument('--write-asset-list',
                      action='store_true',
                      help='Whether to create an assets/assets_list file.')
  parser.add_argument('--uncompressed-assets',
                      help='Same as --assets, except disables compression.',
                      default='[]')
  parser.add_argument('--resource-apk',
                      help='An .ap_ file built using aapt',
                      required=True)
  parser.add_argument('--output-apk',
                      help='Path to the output file',
                      required=True)
  parser.add_argument('--dex-file',
                      help='Path to the classes.dex to use')
  parser.add_argument('--native-libs',
                      action='append',
                      help='GYP-list of native libraries to include. '
                           'Can be specified multiple times.',
                      default=[])
  parser.add_argument('--android-abi',
                      help='Android architecture to use for native libraries')
  parser.add_argument('--native-lib-placeholders',
                      help='GYP-list of native library placeholders to add.',
                      default='[]')
  parser.add_argument('--emma-device-jar',
                      help='Path to emma_device.jar to include.')
  parser.add_argument('--uncompress-shared-libraries',
                      action='store_true',
                      help='Uncompress shared libraries')
  options = parser.parse_args(args)
  options.assets = build_utils.ParseGypList(options.assets)
  options.uncompressed_assets = build_utils.ParseGypList(
      options.uncompressed_assets)
  options.native_lib_placeholders = build_utils.ParseGypList(
      options.native_lib_placeholders)
  all_libs = []
  for gyp_list in options.native_libs:
    all_libs.extend(build_utils.ParseGypList(gyp_list))
  options.native_libs = all_libs

  if not options.android_abi and (options.native_libs or
                                  options.native_lib_placeholders):
    raise Exception('Must specify --android-abi with --native-libs')
  return options


def _SplitAssetPath(path):
  """Returns (src, dest) given an asset path in the form src[:dest]."""
  path_parts = path.split(':')
  src_path = path_parts[0]
  if len(path_parts) > 1:
    dest_path = path_parts[1]
  else:
    dest_path = os.path.basename(src_path)
  return src_path, dest_path


def _ExpandPaths(paths):
  """Converts src:dst into tuples and enumerates files within directories.

  Args:
    paths: Paths in the form "src_path:dest_path"

  Returns:
    A list of (src_path, dest_path) tuples sorted by dest_path (for stable
    ordering within output .apk).
  """
  ret = []
  for path in paths:
    src_path, dest_path = _SplitAssetPath(path)
    if os.path.isdir(src_path):
      for f in build_utils.FindInDirectory(src_path, '*'):
        ret.append((f, os.path.join(dest_path, f[len(src_path) + 1:])))
    else:
      ret.append((src_path, dest_path))
  ret.sort(key=lambda t:t[1])
  return ret


def _AddAssets(apk, path_tuples, disable_compression=False):
  """Adds the given paths to the apk.

  Args:
    apk: ZipFile to write to.
    paths: List of paths (with optional :zipPath suffix) to add.
    disable_compression: Whether to disable compression.
  """
  # Group all uncompressed assets together in the hope that it will increase
  # locality of mmap'ed files.
  for target_compress in (False, True):
    for src_path, dest_path in path_tuples:

      compress = not disable_compression and (
          os.path.splitext(src_path)[1] not in _NO_COMPRESS_EXTENSIONS)
      if target_compress == compress:
        apk_path = 'assets/' + dest_path
        try:
          apk.getinfo(apk_path)
          # Should never happen since write_build_config.py handles merging.
          raise Exception('Multiple targets specified the asset path: %s' %
                          apk_path)
        except KeyError:
          build_utils.AddToZipHermetic(apk, apk_path, src_path=src_path,
                                       compress=compress)


def _CreateAssetsList(path_tuples):
  """Returns a newline-separated list of asset paths for the given paths."""
  dests = sorted(t[1] for t in path_tuples)
  return '\n'.join(dests) + '\n'


def main(args):
  args = build_utils.ExpandFileArgs(args)
  options = _ParseArgs(args)

  native_libs = sorted(options.native_libs)

  input_paths = [options.resource_apk, __file__] + native_libs
  if options.dex_file:
    input_paths.append(options.dex_file)

  if options.emma_device_jar:
    input_paths.append(options.emma_device_jar)

  input_strings = [options.android_abi,
                   options.native_lib_placeholders,
                   options.uncompress_shared_libraries]

  _assets = _ExpandPaths(options.assets)
  _uncompressed_assets = _ExpandPaths(options.uncompressed_assets)

  for src_path, dest_path in itertools.chain(_assets, _uncompressed_assets):
    input_paths.append(src_path)
    input_strings.append(dest_path)

  def on_stale_md5():
    tmp_apk = options.output_apk + '.tmp'
    try:
      # TODO(agrieve): It would be more efficient to combine this step
      # with finalize_apk(), which sometimes aligns and uncompresses the
      # native libraries.
      with zipfile.ZipFile(options.resource_apk) as resource_apk, \
           zipfile.ZipFile(tmp_apk, 'w', zipfile.ZIP_DEFLATED) as out_apk:
        def copy_resource(zipinfo):
          compress = zipinfo.compress_type != zipfile.ZIP_STORED
          build_utils.AddToZipHermetic(out_apk, zipinfo.filename,
                                       data=resource_apk.read(zipinfo.filename),
                                       compress=compress)

        # Make assets come before resources in order to maintain the same file
        # ordering as GYP / aapt. http://crbug.com/561862
        resource_infos = resource_apk.infolist()

        # 1. AndroidManifest.xml
        assert resource_infos[0].filename == 'AndroidManifest.xml'
        copy_resource(resource_infos[0])

        # 2. Assets
        if options.write_asset_list:
          data = _CreateAssetsList(
              itertools.chain(_assets, _uncompressed_assets))
          build_utils.AddToZipHermetic(out_apk, 'assets/assets_list', data=data)

        _AddAssets(out_apk, _assets, disable_compression=False)
        _AddAssets(out_apk, _uncompressed_assets, disable_compression=True)

        # 3. Dex files
        if options.dex_file and options.dex_file.endswith('.zip'):
          with zipfile.ZipFile(options.dex_file, 'r') as dex_zip:
            for dex in (d for d in dex_zip.namelist() if d.endswith('.dex')):
              build_utils.AddToZipHermetic(out_apk, dex, data=dex_zip.read(dex))
        elif options.dex_file:
          build_utils.AddToZipHermetic(out_apk, 'classes.dex',
                                       src_path=options.dex_file)

        # 4. Native libraries.
        for path in native_libs:
          basename = os.path.basename(path)
          apk_path = 'lib/%s/%s' % (options.android_abi, basename)

          compress = None
          if (options.uncompress_shared_libraries and
              os.path.splitext(basename)[1] == '.so'):
            compress = False

          build_utils.AddToZipHermetic(out_apk,
                                       apk_path,
                                       src_path=path,
                                       compress=compress)

        for name in sorted(options.native_lib_placeholders):
          # Empty libs files are ignored by md5check, but rezip requires them
          # to be empty in order to identify them as placeholders.
          apk_path = 'lib/%s/%s' % (options.android_abi, name)
          build_utils.AddToZipHermetic(out_apk, apk_path, data='')

        # 5. Resources
        for info in resource_infos[1:]:
          copy_resource(info)

        # 6. Java resources. Used only when coverage is enabled, so order
        # doesn't matter).
        if options.emma_device_jar:
          # Add EMMA Java resources to APK.
          with zipfile.ZipFile(options.emma_device_jar, 'r') as emma_device_jar:
            for apk_path in emma_device_jar.namelist():
              apk_path_lower = apk_path.lower()
              if apk_path_lower.startswith('meta-inf/'):
                continue

              if apk_path_lower.endswith('/'):
                continue

              if apk_path_lower.endswith('.class'):
                continue

              build_utils.AddToZipHermetic(out_apk, apk_path,
                                           data=emma_device_jar.read(apk_path))

      shutil.move(tmp_apk, options.output_apk)
    finally:
      if os.path.exists(tmp_apk):
        os.unlink(tmp_apk)

  build_utils.CallAndWriteDepfileIfStale(
      on_stale_md5,
      options,
      input_paths=input_paths,
      input_strings=input_strings,
      output_paths=[options.output_apk])


if __name__ == '__main__':
  main(sys.argv[1:])

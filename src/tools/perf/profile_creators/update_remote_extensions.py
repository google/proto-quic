# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import base64
import csv
import json
import optparse
import os
import shutil
import sys
import tempfile
import urllib2
import zipfile

sys.path.insert(1, os.path.abspath(os.path.join(
    __file__, '..', '..')))
from core import path_util


path_util.AddPyUtilsToPath()
from py_utils import cloud_storage

path_util.AddTelemetryToPath()
from telemetry.core import exceptions


# Remote target upload directory in cloud storage for extensions.
REMOTE_DIR = 'extension_set'

# Target zip file.
ZIP_NAME = 'extensions.zip'


def _DownloadCrxFromCws(ext_id, dst):
  """Downloads CRX specified from Chrome Web Store.

  Retrieves CRX (Chrome extension file) specified by ext_id from Chrome Web
  Store, into directory specified by dst.

  Args:
      ext_id: id of extension to retrieve.
      dst: directory to download CRX into

  Returns:
      Returns local path to downloaded CRX.
      If download fails, return None.
  """
  dst_path = os.path.join(dst, '%s.crx' % ext_id)
  cws_url = ('https://clients2.google.com/service/update2/crx?response='
             'redirect&prodversion=38.0&x=id%%3D%s%%26installsource%%3D'
             'ondemand%%26uc' % ext_id)
  response = urllib2.urlopen(cws_url)
  if response.getcode() is not 200:
    return None
  with open(dst_path, 'w') as f:
    f.write(response.read())
  return dst_path


def _UpdateExtensionsInCloud(local_extensions_dir, extensions_csv, remote_dir):
  """Updates set of extensions in Cloud Storage from a CSV of extension ids.

  From well-formatted CSV file containing some set of extensions
  (extensions_csv), download them, compress into archive, and update
  the remote extension archive under REMOTE_DIR in CHROME-PARTNER-TELEMETRY
  bucket. This script expects 2nd column of CSV file to contain extension ids.

  Args:
      local_extensions_dir: directory to download CRX files into.
      extension_csv: CSV to pull extension_ids from.
      remote_dir: remote directory to put extension archive in cloud storage.

  Raises:
      Exception if a CRX download fails.
  """

  # Download CRX to temp files and compress into archive
  zip_path = os.path.join(local_extensions_dir, ZIP_NAME)
  extension_zip = zipfile.ZipFile(zip_path, 'w')
  update_csv = False
  extensions_info = []
  with open(extensions_csv, 'rb') as csv_file:
    reader = csv.reader(csv_file)
    # Stores comments (in case CSV needs to be updated/rewritten)
    # and skips header line.
    comments = []
    line = ','.join(reader.next())
    while line.startswith('#'):
      comments.append(line)
      line = ','.join(reader.next())
    # Extract info from CSV.
    for row in reader:
      extension_info = {
          'extension_name': row[0],
          'id': row[1],
          'hash': row[2],
          'version': row[3]
      }

      print 'Fetching extension %s...' % extension_info['id']
      crx_path = _DownloadCrxFromCws(extension_info['id'], local_extensions_dir)
      if crx_path is None:
        raise exceptions.Error('\tCould not fetch %s.\n\n'
                               'If this extension dl consistently fails, '
                               'remove this entry from %s.'
                               % (extension_info['id'], extensions_csv))
      (new_hash, new_version) = _CrxHashIfChanged(crx_path, extension_info)
      if new_hash is not None:
        update_csv = True
        extension_info['hash'] = new_hash
        extension_info['version'] = new_version
      extensions_info.append(extension_info)
      extension_zip.write(crx_path, arcname='%s.crx' % extension_info['id'])
  extension_zip.close()

  if update_csv:
    print 'Updating CSV...'
    _UpdateCsv(comments, extensions_csv, extensions_info)

  print 'Uploading extensions to cloud...'
  remote_zip_path = os.path.join(remote_dir, ZIP_NAME)
  cloud_storage.Insert(cloud_storage.PARTNER_BUCKET, remote_zip_path, zip_path)


def _CrxHashIfChanged(crx_path, extension_info):
  """Checks whether downloaded Crx has been altered.

  Compares stored hash with hash of downloaded Crx. If different, alerts user
  that CRX version has changed and will be updated in CSV file.

  Args:
    crx_path: Path to downloaded CRX.
    extension_info: Info from CSV (including id and previous hash) about CRX.

  Returns:
    New hash and version if extension differed. Otherwise, returns (None, None)
  """
  downloaded_hash = _Base64Hash(crx_path)
  new_version = _GetVersionFromCrx(crx_path)
  if downloaded_hash != extension_info['hash']:
    if new_version != extension_info['version']:
      ans = raw_input('\tWarning: Extension %s version from Web Store differs '
                      'from CSV version.\n\tIf continued, script will write '
                      'new hash and version to CSV.\n\tContinue? (y/n) '
                      % extension_info['id']).lower()
    else:
      raise exceptions.Error('Extension %s hash from Web Store differs from '
                             '\nhash stored in CSV, but versions are the same.')
    if not ans.startswith('y'):
      sys.exit('Web Store extension %s hash differs from hash in CSV.'
               % extension_info['id'])
    return (downloaded_hash, new_version)
  return (None, None)


def _UpdateCsv(comments, extensions_csv, extensions_info):
  """Updates CSV with information in extensions_info.

  Original CSV is overwritten with updated information about each extension.
  Header comments from original CSV are preserved.

  Args:
    comments: List containing lines of comments found in header of original CSV.
    extensions_csv: Path to CSV file.
    extensions_info: List of extension info to write to CSV. Each entry is
        a dict containing fields extension_name, id, hash, and version.
  """
  # Maintain pre-existing comments.
  with open(extensions_csv, 'w') as csv_file:
    csv_file.write('\n'.join(comments))
    csv_file.write('\n')
  with open(extensions_csv, 'a') as csv_file:
    writer = csv.DictWriter(
        csv_file, fieldnames=['extension_name', 'id', 'hash', 'version'])
    writer.writeheader()
    writer.writerows(extensions_info)


def _GetCsvFromArgs():
  """Parse options to retrieve name of CSV file."""
  parser = optparse.OptionParser()
  parser.add_option('-e', '--extension-csv', dest='extension_csv',
                    help='CSV of extensions to load.')
  (options, _) = parser.parse_args()
  if not options.extension_csv:
    parser.error('Must specify --extension-csv option.')
  return options.extension_csv


def _GetVersionFromCrx(crx_path):
  """Retrieves extension version from CRX archive.

  Args:
    crx_path: path to CRX archive to extract version from.
  """
  with zipfile.ZipFile(crx_path, 'r') as crx_zip:
    manifest_contents = crx_zip.read('manifest.json')
    version = json.loads(manifest_contents)['version']
  return version


def _Base64Hash(file_path):
  return base64.b64encode(cloud_storage.CalculateHash(file_path))


def main():
  extension_csv = _GetCsvFromArgs()
  local_extensions_dir = tempfile.mkdtemp()
  try:
    _UpdateExtensionsInCloud(local_extensions_dir,
                             extension_csv, REMOTE_DIR)
  finally:
    shutil.rmtree(local_extensions_dir)

if __name__ == '__main__':
  main()

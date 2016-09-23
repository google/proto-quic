# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Bisect repackage tool for Linux.

This script repacakges chrome builds for manual bisect script.
"""

from functools import partial
import json
import logging
from multiprocessing import Pool
import optparse
import os
import re
import sys
import tempfile
import threading
import urllib
import bisect_repackage_utils

# Declares required files to run manual bisect script on chrome Linux
# builds in perf. Binary files that should be stripped to reduce zip file
# size are declared. The file list was gotten from the local chrome
# executable path. (This can be retrieved by typing 'chrome://version'
# in chrome and following the executable path. The list needs to be updated if
# future chrome versions require additional files.
CHROME_REQUIRED_FILES = {
    'linux': [
        'chrome',
        'chrome_100_percent.pak',
        'chrome_200_percent.pak',
        'default_apps',
        'icudtl.dat',
        'libwidevinecdm.so',
        'locales',
        'nacl_helper',
        'nacl_helper_bootstrap',
        'nacl_irt_x86_64.nexe',
        'natives_blob.bin',
        'PepperFlash',
        'product_logo_48.png',
        'resources.pak',
        'snapshot_blob.bin',
        'xdg-mime',
        'xdg-settings'
    ],
    'win64': [
        'chrome.dll',
        'chrome.exe',
        'chrome_100_percent.pak',
        'chrome_200_percent.pak',
        'chrome_child.dll',
        'chrome_elf.dll',
        'chrome_watcher.dll',
        'default_apps',
        'd3dcompiler_47.dll',
        'icudtl.dat',
        'libEGL.dll',
        'libGLESv2.dll',
        'locales',
        'nacl_irt_x86_64.nexe',
        'natives_blob.bin',
        'PepperFlash',
        'resources.pak',
        'SecondaryTile.png',
        'snapshot_blob.bin'
    ],
    'mac': [
        'Google Chrome.app'
    ]
}

CHROME_WHITELIST_FILES = {
    # ^$ means not to include any files from whitelist
    'linux': '^$',
    'win64': '^\d+\.\d+\.\d+\.\d+\.manifest$',
    'mac': '^$'
}

CHROME_STRIP_LIST = {
    'linux': [
        'chrome',
        'nacl_helper'
    ],
    'win64': [
        # No stripping symbols from win64 archives
    ],
    'mac': [
        # No stripping symbols from mac archives
    ]
}

# API to convert Githash to Commit position number.
CHROMIUM_GITHASH_TO_SVN_URL = (
    'https://cr-rev.appspot.com/_ah/api/crrev/v1/commit/%s')

REVISION_MAP_FILE = 'revision_map.json'

BUILDER_NAME = {
    'linux': 'Linux Builder',
    'mac': 'Mac Builder',
    'win32': 'Win Builder',
    'win64': 'Win x64 Builder'
}

ARCHIVE_PREFIX = {
    'linux': 'full-build-linux',
    'mac': 'full-build-mac',
    'win32': 'full-build-win32',
    'win64': 'full-build-win32'
}

class ChromeExecutionError(Exception):
  """Raised when Chrome execution fails."""
  pass

class GitConversionError(Exception):
  """Raised when Chrome execution fails."""
  pass

class PathContext(object):
  """Stores information to repackage from a bucket to another.

  A PathContext is used to carry the information used to construct URLs and
  paths when dealing with the storage server and archives.
  """

  def __init__(self, original_gs_url, repackage_gs_url,
               archive, revision_file=REVISION_MAP_FILE):
    super(PathContext, self).__init__()
    self.original_gs_url = original_gs_url
    self.repackage_gs_url = repackage_gs_url
    self.archive = archive
    self.builder_name = BUILDER_NAME[archive]
    self.file_prefix = ARCHIVE_PREFIX[archive]
    self.revision_file = revision_file


def get_cp_from_hash(git_hash):
  """Converts a git hash to commit position number."""
  json_url = CHROMIUM_GITHASH_TO_SVN_URL % git_hash
  response = urllib.urlopen(json_url)
  if response.getcode() == 200:
    try:
      data = json.loads(response.read())
    except Exception,e:
      logging.warning('JSON URL: %s, Error Message: %s' % json_url, e)
      raise GitConversionError
  else:
      logging.warning('JSON URL: %s, Error Message: %s' % json_url, e)
      raise GitConversionError
  if 'number' in data:
    return data['number']
  logging.warning('JSON URL: %s, Error Message: %s' % json_url, e)
  raise GitConversionError


def create_cp_from_hash_map(hash_list):
  """Returns dict used for conversion of hash list.

  Creates a dictionary that maps from Commit position number
  to corresponding GitHash.
  """
  hash_map = {}
  for git_hash in hash_list:
    try:
      cp_num = get_cp_from_hash(git_hash)
      hash_map[cp_num] = git_hash
    except GitConversionError:
      pass
  return hash_map


def get_list_of_suffix(bucket_address, prefix, filter_function):
  """Gets the list of suffixes in files in a google storage bucket.

  Example: a google storage bucket containing one file
  'full-build-linux_20983' will return ['20983'] if prefix is
  provided as 'full-build-linux'. Google Storage bucket
  containing multiple files will return multiple suffixes.

  Args:
    bucket_address(String): Bucket URL to examine files from.
    prefix(String): The prefix used in creating build file names
    filter_function: A function that returns true if the extracted
      suffix is in correct format and false otherwise. It allows
      only proper suffix to be extracted and returned.

  Returns:
    (List) list of proper suffixes in the bucket.
  """
  file_list = bisect_repackage_utils.GSutilList(bucket_address)
  suffix_list = []
  extract_suffix = '.*?%s_(.*?)\.zip' %(prefix)
  for file in file_list:
    match = re.match(extract_suffix, file)
    if match and filter_function(match.groups()[0]):
      suffix_list.append(match.groups()[0])
  return suffix_list


def download_build(cp_num, revision_map, zip_file_name, context):
  """Download a single build corresponding to the cp_num and context."""
  file_url = '%s/%s/%s_%s.zip' %(context.original_gs_url, context.builder_name,
                                 context.file_prefix, revision_map[cp_num])
  bisect_repackage_utils.GSUtilDownloadFile(file_url, zip_file_name)


def upload_build(zip_file, context):
  """Uploads a single build in zip_file to the repackage_gs_url in context."""
  gs_base_url = '%s/%s' %(context.repackage_gs_url, context.builder_name)
  upload_url = gs_base_url + '/'
  bisect_repackage_utils.GSUtilCopy(zip_file, upload_url)


def download_revision_map(context):
  """Downloads the revision map in original_gs_url in context."""
  gs_base_url = '%s/%s' %(context.repackage_gs_url, context.builder_name)
  download_url = gs_base_url + '/' + context.revision_file
  bisect_repackage_utils.GSUtilDownloadFile(download_url,
                                            context.revision_file)


def get_revision_map(context):
  """Downloads and returns the revision map in repackage_gs_url in context."""
  bisect_repackage_utils.RemoveFile(context.revision_file)
  download_revision_map(context)
  with open(context.revision_file, 'r') as revision_file:
    revision_map = json.load(revision_file)
  bisect_repackage_utils.RemoveFile(context.revision_file)
  return revision_map


def upload_revision_map(revision_map, context):
  """Upload the given revision_map to the repackage_gs_url in context."""
  with open(context.revision_file, 'w') as revision_file:
    json.dump(revision_map, revision_file)
  gs_base_url = '%s/%s' %(context.repackage_gs_url, context.builder_name)
  upload_url = gs_base_url + '/'
  bisect_repackage_utils.GSUtilCopy(context.revision_file, upload_url)
  bisect_repackage_utils.RemoveFile(context.revision_file)


def create_upload_revision_map(context):
  """Creates and uploads a dictionary that maps from GitHash to CP number."""
  gs_base_url = '%s/%s' %(context.original_gs_url, context.builder_name)
  hash_list = get_list_of_suffix(gs_base_url, context.file_prefix,
                                 bisect_repackage_utils.IsGitCommitHash)
  cp_num_to_hash_map = create_cp_from_hash_map(hash_list)
  upload_revision_map(cp_num_to_hash_map, context)


def update_upload_revision_map(context):
  """Updates and uploads a dictionary that maps from GitHash to CP number."""
  gs_base_url = '%s/%s' %(context.original_gs_url, context.builder_name)
  revision_map = get_revision_map(context)
  hash_list = get_list_of_suffix(gs_base_url, context.file_prefix,
                                 bisect_repackage_utils.IsGitCommitHash)
  hash_list = list(set(hash_list)-set(revision_map.values()))
  cp_num_to_hash_map = create_cp_from_hash_map(hash_list)
  merged_dict = dict(cp_num_to_hash_map.items() + revision_map.items())
  upload_revision_map(merged_dict, context)


def make_lightweight_archive(file_archive, archive_name, files_to_archive,
                             context, staging_dir):
  """Repackages and strips the archive.

  Repacakges and strips according to CHROME_REQUIRED_FILES and
  CHROME_STRIP_LIST.
  """
  strip_list = CHROME_STRIP_LIST[context.archive]
  tmp_archive = os.path.join(staging_dir, 'tmp_%s' % archive_name)
  (zip_file, zip_dir) = bisect_repackage_utils.MakeZip(tmp_archive,
                                                       archive_name,
                                                       files_to_archive,
                                                       file_archive,
                                                       raise_error=False,
                                                       strip_files=strip_list)
  return (zip_file, zip_dir, tmp_archive)


def remove_created_files_and_path(files, paths):
  """Removes all the files and paths passed in."""
  for file in files:
    bisect_repackage_utils.RemoveFile(file)
  for path in paths:
    bisect_repackage_utils.RemovePath(path)


def verify_chrome_run(zip_dir):
  """This function executes chrome executable in zip_dir.

  Currently, it is only supported for Linux Chrome builds.
  Raises error if the execution fails for any reason.
  """
  try:
    command = [os.path.join(zip_dir, 'chrome')]
    code = bisect_repackage_utils.RunCommand(command)
    if code != 0:
      raise ChromeExecutionError('An error occurred when executing Chrome')
  except ChromeExecutionError,e:
    print str(e)


def get_whitelist_files(extracted_folder, archive):
  """Gets all the files & directories matching whitelisted regex."""
  whitelist_files = []
  all_files = os.listdir(extracted_folder)
  for file in all_files:
    if re.match(CHROME_WHITELIST_FILES[archive], file):
      whitelist_files.append(file)
  return whitelist_files


def repackage_single_revision(revision_map, verify_run, staging_dir,
                              context, cp_num):
  """Repackages a single Chrome build for manual bisect."""
  archive_name = '%s_%s' %(context.file_prefix, cp_num)
  file_archive = os.path.join(staging_dir, archive_name)
  zip_file_name = '%s.zip' % (file_archive)
  download_build(cp_num, revision_map, zip_file_name, context)
  extract_dir = os.path.join(staging_dir, archive_name)
  bisect_repackage_utils.ExtractZip(zip_file_name, extract_dir)
  extracted_folder = os.path.join(extract_dir, context.file_prefix)
  if CHROME_WHITELIST_FILES[context.archive]:
    whitelist_files = get_whitelist_files(extracted_folder, context.archive)
    files_to_include = whitelist_files + CHROME_REQUIRED_FILES[context.archive]
  else:
    files_to_include = CHROME_REQUIRED_FILES[context.archive]
  (zip_dir, zip_file, tmp_archive) = make_lightweight_archive(extracted_folder,
                                                              archive_name,
                                                              files_to_include,
                                                              context,
                                                              staging_dir)

  if verify_run:
    verify_chrome_run(zip_dir)

  upload_build(zip_file, context)
  # Removed temporary files created during repackaging process.
  remove_created_files_and_path([zip_file_name],
                                [zip_dir, extract_dir, tmp_archive])


def repackage_revisions(revisions, revision_map, verify_run, staging_dir,
                        context, quit_event=None, progress_event=None):
  """Repackages all Chrome builds listed in revisions.

  This function calls 'repackage_single_revision' with multithreading pool.
  """
  p = Pool(3)
  func = partial(repackage_single_revision, revision_map, verify_run,
                 staging_dir, context)
  p.imap(func, revisions)
  p.close()
  p.join()


def get_uploaded_builds(context):
  """Returns already uploaded revisions in original bucket."""
  gs_base_url = '%s/%s' %(context.repackage_gs_url, context.builder_name)
  return get_list_of_suffix(gs_base_url, context.file_prefix,
                            bisect_repackage_utils.IsCommitPosition)


def get_revisions_to_package(revision_map, context):
  """Returns revisions that need to be repackaged.

  It subtracts revisions that are already packaged from all revisions that
  need to be packaged. The revisions will be sorted in descending order.
  """
  already_packaged = get_uploaded_builds(context)
  not_already_packaged = list(set(revision_map.keys())-set(already_packaged))
  revisions_to_package = sorted(not_already_packaged, reverse=True)
  return revisions_to_package


class RepackageJob(object):

  def __init__(self, name, revisions_to_package, revision_map, verify_run,
               staging_dir, context):
    super(RepackageJob, self).__init__()
    self.name = name
    self.revisions_to_package = revisions_to_package
    self.revision_map = revision_map
    self.verify_run = verify_run
    self.staging_dir = staging_dir
    self.context = context
    self.quit_event = threading.Event()
    self.progress_event = threading.Event()
    self.thread = None

  def Start(self):
    """Starts the download."""
    fetchargs = (self.revisions_to_package,
                 self.revision_map,
                 self.verify_run,
                 self.staging_dir,
                 self.context,
                 self.quit_event,
                 self.progress_event)
    self.thread = threading.Thread(target=repackage_revisions,
                                   name=self.name,
                                   args=fetchargs)
    self.thread.start()

  def Stop(self):
    """Stops the download which must have been started previously."""
    assert self.thread, 'DownloadJob must be started before Stop is called.'
    self.quit_event.set()
    self.thread.join()

  def WaitFor(self):
    """Prints a message and waits for the download to complete."""
    assert self.thread, 'DownloadJob must be started before WaitFor is called.'
    self.progress_event.set()  # Display progress of download.  def Stop(self):
    assert self.thread, 'DownloadJob must be started before Stop is called.'
    self.quit_event.set()
    self.thread.join()


def main(argv):
  option_parser = optparse.OptionParser()

  choices = ['mac', 'win32', 'win64', 'linux']

  option_parser.add_option('-a', '--archive',
                           choices=choices,
                           help='Builders to repacakge from [%s].' %
                           '|'.join(choices))

  # Verifies that the chrome executable runs
  option_parser.add_option('-v', '--verify',
                           action='store_true',
                           help='Verifies that the Chrome executes normally'
                                'without errors')

  # This option will update the revision map.
  option_parser.add_option('-u', '--update',
                           action='store_true',
                           help='Updates the list of revisions to repackage')

  # This option will creates the revision map.
  option_parser.add_option('-c', '--create',
                           action='store_true',
                           help='Creates the list of revisions to repackage')

  # Original bucket that contains perf builds
  option_parser.add_option('-o', '--original',
                           type='str',
                           help='Google storage url containing original'
                                'Chrome builds')

  # Bucket that should archive lightweight perf builds
  option_parser.add_option('-r', '--repackage',
                           type='str',
                           help='Google storage url to re-archive Chrome'
                                'builds')

  verify_run = False
  (opts, args) = option_parser.parse_args()
  if opts.archive is None:
    print 'Error: missing required parameter: --archive'
    option_parser.print_help()
    return 1
  if not opts.original or not opts.repackage:
    raise ValueError('Need to specify original gs bucket url and'
                     'repackage gs bucket url')
  context = PathContext(opts.original, opts.repackage, opts.archive)

  if opts.create:
    create_upload_revision_map(context)

  if opts.update:
    update_upload_revision_map(context)

  if opts.verify:
    verify_run = True

  revision_map = get_revision_map(context)
  backward_rev = get_revisions_to_package(revision_map, context)
  base_dir = os.path.join('.', context.archive)
  # Clears any uncleared staging directories and create one
  bisect_repackage_utils.RemovePath(base_dir)
  bisect_repackage_utils.MaybeMakeDirectory(base_dir)
  staging_dir = os.path.abspath(tempfile.mkdtemp(prefix='staging',
                                                 dir=base_dir))
  repackage = RepackageJob('backward_fetch', backward_rev, revision_map,
                           verify_run, staging_dir, context)
  # Multi-threading is not currently being used. But it can be used in
  # cases when the repackaging needs to be quicker.
  try:
    repackage.Start()
    repackage.WaitFor()
  except (KeyboardInterrupt, SystemExit):
    print 'Cleaning up...'
    bisect_repackage_utils.RemovePath(staging_dir)
  print 'Cleaning up...'
  bisect_repackage_utils.RemovePath(staging_dir)


if '__main__' == __name__:
  sys.exit(main(sys.argv))

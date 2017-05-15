# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utilities for scanning source files to determine code authorship.
"""

import itertools

def ForwardSlashesToOsPathSeps(input_api, path):
  """Converts forward slashes ('/') in the input path to OS-specific
  path separators. Used when the paths come from outside and are using
  UNIX path separators. Only works for relative paths!
  Args:
    input_api: InputAPI, as in presubmit scripts.
    path: The path to convert.
  Returns:
    Converted path.
  """
  return input_api.os_path.join(*path.split('/'))

def FindFiles(input_api, root_dir, start_paths_list, excluded_dirs_list):
  """Similar to UNIX utility find(1), searches for files in the directories.
  Automatically leaves out only source code files and excludes third_party
  directories.
  Args:
    input_api: InputAPI, as in presubmit scripts.
    root_dir: The root directory, to which all other paths are relative.
    start_paths_list: The list of paths to start search from. Each path can
      be a file or a directory.
    excluded_dirs_list: The list of directories to skip.
  Returns:
    The list of source code files found, relative to |root_dir|.
  """
  excluded_dirs_list = [d for d in excluded_dirs_list if not 'third_party' in d]
  # Using a common pattern for third-partyies makes the ignore regexp shorter
  excluded_dirs_list.append('third_party')

  path_join = input_api.os_path.join
  EXTRA_EXCLUDED_DIRS = [
    # VCS dirs
    path_join('.git'),
    path_join('.svn'),
    # Build output
    path_join('out', 'Debug'),
    path_join('out', 'Release'),
    # 'Copyright' appears in license agreements
    path_join('chrome', 'app', 'resources'),
    # Quickoffice js files from internal src used on buildbots.
    # crbug.com/350472.
    path_join('chrome', 'browser', 'resources', 'chromeos', 'quickoffice'),
    # blink style copy right headers.
    path_join('content', 'shell', 'renderer', 'test_runner'),
    # blink style copy right headers.
    path_join('content', 'shell', 'tools', 'plugin'),
    # This is tests directory, doesn't exist in the snapshot
    path_join('content', 'test', 'data'),
    # This is a tests directory that doesn't exist in the shipped product.
    path_join('gin', 'test'),
    # This is a test output directory
    path_join('data', 'dom_perf'),
    # This is a tests directory that doesn't exist in the shipped product.
    path_join('tools', 'perf', 'page_sets'),
    path_join('tools', 'perf', 'page_sets', 'tough_animation_cases'),
    # Histogram tools, doesn't exist in the snapshot
    path_join('tools', 'histograms'),
    # Swarming tools, doesn't exist in the snapshot
    path_join('tools', 'swarming_client'),
    # Don't check downloaded goma client binaries.
    path_join('build', 'goma', 'client'),
    # Ignore sysroots.
    path_join('build', 'linux', 'debian_jessie_arm64-sysroot'),
    path_join('build', 'linux', 'debian_jessie_arm-sysroot'),
    path_join('build', 'linux', 'debian_jessie_mips-sysroot'),
    path_join('build', 'linux', 'debian_jessie_i386-sysroot'),
    path_join('build', 'linux', 'debian_jessie_amd64-sysroot'),
    # Data is not part of open source chromium, but are included on some bots.
    path_join('data'),
    # This is not part of open source chromium, but are included on some bots.
    path_join('skia', 'tools', 'clusterfuzz-data'),
    # Not shipped, only relates to Chrome for Android, but not to WebView
    path_join('clank'),
    # Internal-only repository.
    path_join('remoting', 'android', 'internal'),
  ]
  excluded_dirs_list.extend(EXTRA_EXCLUDED_DIRS)

  # Surround the directory names with OS path separators.
  dirs_blacklist = [path_join('.', d, '')[1:] for d in excluded_dirs_list if d]
  def IsBlacklistedDir(d):
    for item in dirs_blacklist:
      if item in d:
        return True
    return False

  files_whitelist_re = input_api.re.compile(
    r'\.(asm|c(c|pp|xx)?|h(h|pp|xx)?|p(l|m)|xs|sh|php|py(|x)'
    '|rb|idl|java|el|sc(i|e)|cs|pas|inc|js|pac|html|dtd|xsl|mod|mm?'
    '|tex|mli?)$')
  files = []

  base_path_len = len(root_dir)
  for path in start_paths_list:
    full_path = path_join(root_dir, path)
    if input_api.os_path.isfile(full_path):
      if files_whitelist_re.search(path) and \
          not IsBlacklistedDir(full_path[base_path_len:]):  # Keep '/' prefix.
        files.append(path)
    else:
      for dirpath, dirnames, filenames in input_api.os_walk(full_path):
        # Remove excluded subdirs for faster scanning.
        for item in dirnames[:]:
          if IsBlacklistedDir(
              path_join(dirpath, item)[base_path_len + 1:]):
            dirnames.remove(item)
        for filename in filenames:
          filepath = \
              path_join(dirpath, filename)[base_path_len + 1:]
          if files_whitelist_re.search(filepath) and \
              not IsBlacklistedDir(filepath):
            files.append(filepath)
  return files


class _GeneratedFilesDetector(object):
  GENERATED_FILE = 'GENERATED FILE'
  NO_COPYRIGHT = '*No copyright*'

  def __init__(self, input_api):
    self.python_multiline_string_double_re = \
      input_api.re.compile(r'"""[^"]*(?:"""|$)', flags=input_api.re.MULTILINE)
    self.python_multiline_string_single_re = \
      input_api.re.compile(r"'''[^']*(?:'''|$)", flags=input_api.re.MULTILINE)
    self.automatically_generated_re = input_api.re.compile(
      r'(All changes made in this file will be lost'
      '|DO NOT (EDIT|delete this file)'
      '|Generated (at|automatically|data)'
      '|Automatically generated'
      '|\Wgenerated\s+(?:\w+\s+)*file\W)', flags=input_api.re.IGNORECASE)

  def IsGeneratedFile(self, header):
    header = header.upper()
    if '"""' in header:
      header = self.python_multiline_string_double_re.sub('', header)
    if "'''" in header:
      header = self.python_multiline_string_single_re.sub('', header)
    # First do simple strings lookup to save time.
    if 'ALL CHANGES MADE IN THIS FILE WILL BE LOST' in header:
      return True
    if 'DO NOT EDIT' in header or 'DO NOT DELETE' in header or \
        'GENERATED' in header:
      return self.automatically_generated_re.search(header)
    return False


class _CopyrightsScanner(object):
  @staticmethod
  def StaticInit(input_api):
    _CopyrightsScanner._c_comment_re = \
      input_api.re.compile(r'''"[^"\\]*(?:\\.[^"\\]*)*"''')
    _CopyrightsScanner._copyright_indicator = \
      r'(?:copyright|copr\.|\xc2\xa9|\(c\))'
    _CopyrightsScanner._full_copyright_indicator_re = input_api.re.compile(
      r'(?:\W|^)' + _CopyrightsScanner._copyright_indicator + \
      r'(?::\s*|\s+)(\w.*)$', input_api.re.IGNORECASE)
    _CopyrightsScanner._copyright_disindicator_re = input_api.re.compile(
      r'\s*\b(?:info(?:rmation)?|notice|and|or)\b', input_api.re.IGNORECASE)

  def __init__(self, input_api):
    self.max_line_numbers_proximity = 3
    self.last_a_item_line_number = -200
    self.last_b_item_line_number = -100
    self.re = input_api.re

  def _CloseLineNumbers(self, a, b):
    return 0 <= a - b <= self.max_line_numbers_proximity

  def MatchLine(self, line_number, line):
    if '"' in line:
      line = _CopyrightsScanner._c_comment_re.sub('', line)
    upcase_line = line.upper()
    # Record '(a)' and '(b)' last occurences in C++ comments.
    # This is to filter out '(c)' used as a list item inside C++ comments.
    # E.g. "// blah-blah (a) blah\n// blah-blah (b) and (c) blah"
    cpp_comment_idx = upcase_line.find('//')
    if cpp_comment_idx != -1:
      if upcase_line.find('(A)') > cpp_comment_idx:
        self.last_a_item_line_number = line_number
      if upcase_line.find('(B)') > cpp_comment_idx:
        self.last_b_item_line_number = line_number
    # Fast bailout, uses the same patterns as _copyright_indicator regexp.
    if not 'COPYRIGHT' in upcase_line and not 'COPR.' in upcase_line \
        and not '\xc2\xa9' in upcase_line:
      c_item_index = upcase_line.find('(C)')
      if c_item_index == -1:
        return None
      if c_item_index > cpp_comment_idx and \
          self._CloseLineNumbers(line_number,
                                 self.last_b_item_line_number) and \
          self._CloseLineNumbers(self.last_b_item_line_number,
                                 self.last_a_item_line_number):
        return None
    copyr = None
    m = _CopyrightsScanner._full_copyright_indicator_re.search(line)
    if m and \
        not _CopyrightsScanner._copyright_disindicator_re.match(m.group(1)):
      copyr = m.group(0)
      # Prettify the authorship string.
      copyr = self.re.sub(r'([,.])?\s*$/', '', copyr)
      copyr = self.re.sub(
        _CopyrightsScanner._copyright_indicator, '', copyr, \
        flags=self.re.IGNORECASE)
      copyr = self.re.sub(r'^\s+', '', copyr)
      copyr = self.re.sub(r'\s{2,}', ' ', copyr)
      copyr = self.re.sub(r'\\@', '@', copyr)
    return copyr


def FindCopyrights(input_api, root_dir, files_to_scan):
  """Determines code autorship, and finds generated files.
  Args:
    input_api: InputAPI, as in presubmit scripts.
    root_dir: The root directory, to which all other paths are relative.
    files_to_scan: The list of file names to scan.
  Returns:
    The list of copyrights associated with each of the files given.
    If the certain file is generated, the corresponding list consists a single
    entry -- 'GENERATED_FILE' string. If the file has no copyright info,
    the corresponding list contains 'NO_COPYRIGHT' string.
  """
  generated_files_detector = _GeneratedFilesDetector(input_api)
  _CopyrightsScanner.StaticInit(input_api)
  copyrights = []
  for file_name in files_to_scan:
    linenum = 0
    header = []
    file_copyrights = []
    scanner = _CopyrightsScanner(input_api)
    contents = input_api.ReadFile(
      input_api.os_path.join(root_dir, file_name), 'r')
    for l in contents.split('\n'):
      linenum += 1
      if linenum <= 25:
        header.append(l)
      c = scanner.MatchLine(linenum, l)
      if c:
        file_copyrights.append(c)
    if generated_files_detector.IsGeneratedFile('\n'.join(header)):
      copyrights.append([_GeneratedFilesDetector.GENERATED_FILE])
    elif file_copyrights:
      copyrights.append(file_copyrights)
    else:
      copyrights.append([_GeneratedFilesDetector.NO_COPYRIGHT])
  return copyrights


def FindCopyrightViolations(input_api, root_dir, files_to_scan):
  """Looks for files that are not belong exlusively to the Chromium Authors.
  Args:
    input_api: InputAPI, as in presubmit scripts.
    root_dir: The root directory, to which all other paths are relative.
    files_to_scan: The list of file names to scan.
  Returns:
    The list of file names that contain non-Chromium copyrights.
  """
  copyrights = FindCopyrights(input_api, root_dir, files_to_scan)
  offending_files = []
  allowed_copyrights_re = input_api.re.compile(
    r'^(?:20[0-9][0-9](?:-20[0-9][0-9])? The Chromium Authors\. '
    'All rights reserved.*)$')
  for f, cs in itertools.izip(files_to_scan, copyrights):
    if cs[0] == _GeneratedFilesDetector.GENERATED_FILE or \
       cs[0] == _GeneratedFilesDetector.NO_COPYRIGHT:
      continue
    for c in cs:
      if not allowed_copyrights_re.match(c):
        offending_files.append(input_api.os_path.normpath(f))
        break
  return offending_files


def _GetWhitelistFileName(input_api):
  return input_api.os_path.join(
    'tools', 'copyright_scanner', 'third_party_files_whitelist.txt')

def _ProcessWhitelistedFilesList(input_api, lines):
  whitelisted_files = []
  for line in lines:
    match = input_api.re.match(r'([^#\s]+)', line)
    if match:
      whitelisted_files.append(
        ForwardSlashesToOsPathSeps(input_api, match.group(1)))
  return whitelisted_files


def LoadWhitelistedFilesList(input_api):
  """Loads and parses the 3rd party code whitelist file.
    input_api: InputAPI of presubmit scripts.
  Returns:
    The list of files.
  """
  full_file_name = input_api.os_path.join(
    input_api.change.RepositoryRoot(), _GetWhitelistFileName(input_api))
  file_data = input_api.ReadFile(full_file_name, 'rb')
  return _ProcessWhitelistedFilesList(input_api, file_data.splitlines())


def AnalyzeScanResults(input_api, whitelisted_files, offending_files):
  """Compares whitelist contents with the results of file scanning.
    input_api: InputAPI of presubmit scripts.
    whitelisted_files: Whitelisted files list.
    offending_files: Files that contain 3rd party code.
  Returns:
    A triplet of "unknown", "missing", and "stale" file lists.
    "Unknown" are files that contain 3rd party code but not whitelisted.
    "Missing" are files that are whitelisted but doesn't really exist.
    "Stale" are files that are whitelisted unnecessarily.
  """
  unknown = set(offending_files) - set(whitelisted_files)
  missing = [f for f in whitelisted_files if not input_api.os_path.isfile(
    input_api.os_path.join(input_api.change.RepositoryRoot(), f))]
  stale = set(whitelisted_files) - set(offending_files) - set(missing)
  return (list(unknown), missing, list(stale))


def _GetDeletedContents(affected_file):
  """Returns a list of all deleted lines.
  AffectedFile class from presubmit_support is lacking this functionality.
  """
  deleted_lines = []
  for line in affected_file.GenerateScmDiff().splitlines():
    if line.startswith('-') and not line.startswith('--'):
      deleted_lines.append(line[1:])
  return deleted_lines

def _DoScanAtPresubmit(input_api, whitelisted_files, files_to_check):
  # We pass empty 'known third-party' dirs list here. Since this is a patch
  # for the Chromium's src tree, it must contain properly licensed Chromium
  # code. Any third-party code must be put into a directory named 'third_party',
  # and such dirs are automatically excluded by FindFiles.
  files_to_scan = FindFiles(
    input_api, input_api.change.RepositoryRoot(), files_to_check, [])
  offending_files = FindCopyrightViolations(
    input_api, input_api.change.RepositoryRoot(), files_to_scan)
  return AnalyzeScanResults(
    input_api, whitelisted_files, offending_files)

def ScanAtPresubmit(input_api, output_api):
  """Invoked at change presubmit time. Verifies that updated non third-party
  code doesn't contain external copyrighted code.
    input_api: InputAPI of presubmit scripts.
    output_api: OutputAPI of presubmit scripts.
  """
  files_to_check = set([])
  deleted_files = set([])
  whitelist_contents_changed = False
  for f in input_api.AffectedFiles():
    if f.LocalPath() == _GetWhitelistFileName(input_api):
      whitelist_contents_changed = True
      deleted_files |= set(_ProcessWhitelistedFilesList(
        input_api, _GetDeletedContents(f)))
      continue
    if f.Action() != 'D':
      files_to_check.add(f.LocalPath())
    else:
      deleted_files.add(f.LocalPath())
  whitelisted_files = set(LoadWhitelistedFilesList(input_api))
  if not whitelist_contents_changed:
    whitelisted_files &= files_to_check | deleted_files
  else:
    # Need to re-check the entire contents of the whitelist file.
    # Also add files removed from the whitelist. If the file has indeed been
    # deleted, the scanner will not complain.
    files_to_check |= whitelisted_files | deleted_files

  (unknown_files, missing_files, stale_files) = _DoScanAtPresubmit(
    input_api, list(whitelisted_files), list(files_to_check))
  results = []
  if unknown_files:
    results.append(output_api.PresubmitError(
        'The following files contain a third-party license but are not in ' \
        'a listed third-party directory and are not whitelisted. You must ' \
        'add the following files to the whitelist file %s\n' \
        '(Note that if the code you are adding does not actually contain ' \
        'any third-party code, it may contain the word "copyright", which ' \
        'should be masked out, e.g. by writing it as "copy-right"):' \
        '' % _GetWhitelistFileName(input_api),
        sorted(unknown_files)))
  if missing_files:
    results.append(output_api.PresubmitPromptWarning(
        'The following files are whitelisted in %s, ' \
        'but do not exist or not files:' % _GetWhitelistFileName(input_api),
        sorted(missing_files)))
  if stale_files:
    results.append(output_api.PresubmitPromptWarning(
        'The following files are whitelisted unnecessarily. You must ' \
        'remove the following files from the whitelist file ' \
        '%s:' % _GetWhitelistFileName(input_api),
        sorted(stale_files)))
  return results

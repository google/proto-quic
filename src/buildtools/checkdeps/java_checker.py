# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Checks Java files for illegal imports."""

import codecs
import os
import re

import results
from rules import Rule


class JavaChecker(object):
  """Import checker for Java files.

  The CheckFile method uses real filesystem paths, but Java imports work in
  terms of package names. To deal with this, we have an extra "prescan" pass
  that reads all the .java files and builds a mapping of class name -> filepath.
  In CheckFile, we convert each import statement into a real filepath, and check
  that against the rules in the DEPS files.

  Note that in Java you can always use classes in the same directory without an
  explicit import statement, so these imports can't be blocked with DEPS files.
  But that shouldn't be a problem, because same-package imports are pretty much
  always correct by definition. (If we find a case where this is *not* correct,
  it probably means the package is too big and needs to be split up.)

  Properties:
    _classmap: dict of fully-qualified Java class name -> filepath
  """

  EXTENSIONS = ['.java']

  # This regular expression will be used to extract filenames from import
  # statements.
  _EXTRACT_IMPORT_PATH = re.compile('^import\s+(?:static\s+)?([\w\.]+)\s*;')

  def __init__(self, base_directory, verbose):
    self._base_directory = base_directory
    self._verbose = verbose
    self._classmap = {}
    self._PrescanFiles()

  def _IgnoreDir(self, d):
    # Skip hidden directories.
    if d.startswith('.'):
      return True
    # Skip the "out" directory, as dealing with generated files is awkward.
    # We don't want paths like "out/Release/lib.java" in our DEPS files.
    # TODO(husky): We need some way of determining the "real" path to
    # a generated file -- i.e., where it would be in source control if
    # it weren't generated.
    if d.startswith('out') or d in ('xcodebuild',):
      return True
    # Skip third-party directories.
    if d in ('third_party', 'ThirdParty'):
      return True
    return False

  def _PrescanFiles(self):
    for root, dirs, files in os.walk(self._base_directory):
      # Skip unwanted subdirectories. TODO(husky): it would be better to do
      # this via the skip_child_includes flag in DEPS files. Maybe hoist this
      # prescan logic into checkdeps.py itself?
      dirs[:] = [d for d in dirs if not self._IgnoreDir(d)]
      for f in files:
        if f.endswith('.java'):
          self._PrescanFile(os.path.join(root, f))

  def _PrescanFile(self, filepath):
    if self._verbose:
      print 'Prescanning: ' + filepath
    with codecs.open(filepath, encoding='utf-8') as f:
      short_class_name, _ = os.path.splitext(os.path.basename(filepath))
      for line in f:
        for package in re.findall('^package\s+([\w\.]+);', line):
          full_class_name = package + '.' + short_class_name
          if full_class_name in self._classmap:
            print 'WARNING: multiple definitions of %s:' % full_class_name
            print '    ' + filepath
            print '    ' + self._classmap[full_class_name]
            print
          else:
            self._classmap[full_class_name] = filepath
          return
      print 'WARNING: no package definition found in %s' % filepath

  def CheckLine(self, rules, line, filepath, fail_on_temp_allow=False):
    """Checks the given line with the given rule set.

    Returns a tuple (is_import, dependency_violation) where
    is_import is True only if the line is an import
    statement, and dependency_violation is an instance of
    results.DependencyViolation if the line violates a rule, or None
    if it does not.
    """
    found_item = self._EXTRACT_IMPORT_PATH.match(line)
    if not found_item:
      return False, None  # Not a match
    clazz = found_item.group(1)
    if clazz not in self._classmap:
      # Importing a class from outside the Chromium tree. That's fine --
      # it's probably a Java or Android system class.
      return True, None
    import_path = os.path.relpath(
        self._classmap[clazz], self._base_directory)
    # Convert Windows paths to Unix style, as used in DEPS files.
    import_path = import_path.replace(os.path.sep, '/')
    rule = rules.RuleApplyingTo(import_path, filepath)
    if (rule.allow == Rule.DISALLOW or
        (fail_on_temp_allow and rule.allow == Rule.TEMP_ALLOW)):
      return True, results.DependencyViolation(import_path, rule, rules)
    return True, None

  def CheckFile(self, rules, filepath):
    if self._verbose:
      print 'Checking: ' + filepath

    dependee_status = results.DependeeStatus(filepath)
    with codecs.open(filepath, encoding='utf-8') as f:
      for line in f:
        is_import, violation = self.CheckLine(rules, line, filepath)
        if violation:
          dependee_status.AddViolation(violation)
        if '{' in line:
          # This is code, so we're finished reading imports for this file.
          break

    return dependee_status

  @staticmethod
  def IsJavaFile(filepath):
    """Returns True if the given path ends in the extensions
    handled by this checker.
    """
    return os.path.splitext(filepath)[1] in JavaChecker.EXTENSIONS

  def ShouldCheck(self, file_path):
    """Check if the new import file path should be presubmit checked.

    Args:
      file_path: file path to be checked

    Return:
      bool: True if the file should be checked; False otherwise.
    """
    return self.IsJavaFile(file_path)

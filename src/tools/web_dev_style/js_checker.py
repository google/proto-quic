# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Presubmit script for Chromium JS resources.

See chrome/browser/PRESUBMIT.py
"""

import regex_check


class JSChecker(object):
  def __init__(self, input_api, output_api, file_filter=None):
    self.input_api = input_api
    self.output_api = output_api
    self.file_filter = file_filter

  def RegexCheck(self, line_number, line, regex, message):
    return regex_check.RegexCheck(
        self.input_api.re, line_number, line, regex, message)

  def ChromeSendCheck(self, i, line):
    """Checks for a particular misuse of 'chrome.send'."""
    return self.RegexCheck(i, line, r"chrome\.send\('[^']+'\s*(, \[\])\)",
        'Passing an empty array to chrome.send is unnecessary')

  def CommentIfAndIncludeCheck(self, line_number, line):
    return self.RegexCheck(line_number, line, r'(?<!\/\/ )(<if|<include) ',
        '<if> or <include> should be in a single line comment with a space ' +
        'after the slashes. Examples:\n' +
        '    // <include src="...">\n' +
        '    // <if expr="chromeos">\n' +
        '    // </if>\n')

  def ConstCheck(self, i, line):
    """Check for use of the 'const' keyword."""
    if self.input_api.re.search(r'\*\s+@const', line):
      # Probably a JsDoc line
      return ''

    return self.RegexCheck(i, line, r'(?:^|\s|\()(const)\s',
        'Use /** @const */ var varName; instead of const varName;')

  def EndJsDocCommentCheck(self, i, line):
    msg = 'End JSDoc comments with */ instead of **/'
    def _check(regex):
      return self.RegexCheck(i, line, regex, msg)
    return _check(r'^\s*(\*\*/)\s*$') or _check(r'/\*\* @[a-zA-Z]+.* (\*\*/)')

  def ExtraDotInGenericCheck(self, i, line):
    return self.RegexCheck(i, line, r"((?:Array|Object|Promise)\.<)",
        "Don't use a dot after generics (Object.<T> should be Object<T>).")

  def GetElementByIdCheck(self, i, line):
    """Checks for use of 'document.getElementById' instead of '$'."""
    return self.RegexCheck(i, line, r"(document\.getElementById)\('",
        "Use $('id') or getSVGElement('id') from chrome://resources/js/util.js "
        "instead of document.getElementById('id')")

  def InheritDocCheck(self, i, line):
    """Checks for use of '@inheritDoc' instead of '@override'."""
    return self.RegexCheck(i, line, r"\* (@inheritDoc)",
        "@inheritDoc is deprecated, use @override instead")

  def PolymerLocalIdCheck(self, i, line):
    """Checks for use of element.$.localId."""
    return self.RegexCheck(i, line, r"(?<!this)(\.\$)[\[\.]",
        "Please only use this.$.localId, not element.$.localId")

  def WrapperTypeCheck(self, i, line):
    """Check for wrappers (new String()) instead of builtins (string)."""
    return self.RegexCheck(i, line,
        r"(?:/\*)?\*.*?@(?:param|return|type) ?"     # /** @param/@return/@type
        r"{[^}]*\b(String|Boolean|Number)\b[^}]*}",  # {(Boolean|Number|String)}
        "Don't use wrapper types (i.e. new String() or @type {String})")

  def VarNameCheck(self, i, line):
    """See the style guide. http://goo.gl/eQiXVW"""
    return self.RegexCheck(i, line,
        r"var (?!g_\w+)(_?[a-z][a-zA-Z]*[_$][\w_$]*)(?<! \$)",
        "Please use var namesLikeThis <https://goo.gl/eQiXVW>")

  def _GetErrorHighlight(self, start, length):
    """Takes a start position and a length, and produces a row of '^'s to
       highlight the corresponding part of a string.
    """
    return start * ' ' + length * '^'

  def RunChecks(self):
    """Check for violations of the Chromium JavaScript style guide. See
       https://chromium.googlesource.com/chromium/src/+/master/styleguide/web/web.md#JavaScript
    """
    results = []

    affected_files = self.input_api.AffectedFiles(file_filter=self.file_filter,
                                                  include_deletes=False)
    affected_js_files = filter(lambda f: f.LocalPath().endswith('.js'),
                               affected_files)
    for f in affected_js_files:
      error_lines = []

      for i, line in enumerate(f.NewContents(), start=1):
        error_lines += filter(None, [
            self.ChromeSendCheck(i, line),
            self.CommentIfAndIncludeCheck(i, line),
            self.ConstCheck(i, line),
            self.GetElementByIdCheck(i, line),
            self.EndJsDocCommentCheck(i, line),
            self.ExtraDotInGenericCheck(i, line),
            self.InheritDocCheck(i, line),
            self.PolymerLocalIdCheck(i, line),
            self.WrapperTypeCheck(i, line),
            self.VarNameCheck(i, line),
        ])

      if error_lines:
        error_lines = [
            'Found JavaScript style violations in %s:' %
            f.LocalPath()] + error_lines
        results.append(self.output_api.PresubmitError('\n'.join(error_lines)))

    if results:
      results.append(self.output_api.PresubmitNotifyResult(
          'See the JavaScript style guide at '
          'https://chromium.googlesource.com/chromium/src/+/master/styleguide/web/web.md#JavaScript'))

    return results

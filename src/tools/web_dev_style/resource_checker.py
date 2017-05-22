# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Presubmit for Chromium HTML/CSS/JS resources. See chrome/browser/PRESUBMIT.py.
"""

import regex_check


class ResourceChecker(object):
  def __init__(self, input_api, output_api, file_filter=None):
    self.input_api = input_api
    self.output_api = output_api
    self.file_filter = file_filter

  def IncludeCheck(self, line_number, line):
    return regex_check.RegexCheck(self.input_api.re, line_number, line,
        "(</include>|<include.*/>)", "Closing <include> tags is unnecessary.")

  def RunChecks(self):
    """Check for violations of the Chromium web development style guide. See
       https://chromium.googlesource.com/chromium/src/+/master/styleguide/web/web.md
    """
    results = []

    affected_files = self.input_api.AffectedFiles(file_filter=self.file_filter,
                                                  include_deletes=False)

    for f in affected_files:
      errors = []

      for line_number, line in enumerate(f.NewContents(), start=1):
        error = self.IncludeCheck(line_number, line)
        if error:
          errors.append(error)

      if errors:
        abs_local_path = f.AbsoluteLocalPath()
        file_indicator = 'Found resources style issues in %s' % abs_local_path
        prompt_msg = file_indicator + '\n\n' + '\n'.join(errors) + '\n'
        results.append(self.output_api.PresubmitPromptWarning(prompt_msg))

    return results

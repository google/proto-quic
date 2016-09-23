# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Implement filtering out closure compiler errors due to incorrect type-
checking on promise-based return types.

The compiler's type-checker doesn't correctly unwrap Promised return values
prior to type-checking them.  There are a couple of scenarios where this occurs,
examples can be found below in the code that deals with each specific scenario.

This filtering code applies a set of matchers to the errors that the compiler
emits.  Each matcher fits a known pattern for compiler errors arising from the
issue described above.  If any of the matchers matches an error, that error is
filtered out of the error list.

Note that this is just a coarse filter.  It doesn't, for example, check that the
unwrapped promise type actually matches the type accepted by the next callback
in the Promise chain.  Doing so would be the correct way to fix this problem,
but that fix belongs in the compiler.

"""

import re


class PromiseErrorFilter:
  """Runs checks to filter out promise chain errors."""
  def __init__(self):
    self._allowed_error_patterns = [
      ChainedPromisePattern(),
      ReturnedPromisePattern()
    ]

  def filter(self, error_list):
    """Filters out errors matching any of the allowed patterns.

    Args:
        error_list: A list of errors from the closure compiler.

    Return:
        A list of errors, with spurious Promise type errors removed.
    """
    return [error for error in error_list if not self._should_ignore(error)];

  def _should_ignore(self, error):
    """Check the given error against all the filters.  An error should be
    ignored if it is a match for any of the allowed message patterns.

    Args:
        error: A single entry from the closure compiler error list.

    Return:
        True if the error should be ignored, False otherwise.
    """
    return any([pattern.match(error)
                for pattern in self._allowed_error_patterns]);


class ErrorPattern:
  """A matcher for compiler error messages.  This matches compiler type errors,
  which look like:
    # ERROR - <some error message>
    # found   : <some type expression>
    # required: <some type expression>
  The message and type expressions are customizable.
  """
  def __init__(self, msg, found_pattern, required_pattern):
    # A string literal that is compared to the first line of the error.
    self._error_msg = msg
    # A regex for matching the found type.
    self._found_line_regex = re.compile("found\s*:\s*" + found_pattern)
    # A regex for matching the required type.
    self._required_line_regex = re.compile("required:\s*" + required_pattern)

  def match(self, error):
    error_lines = error.split('\n')

    # Match the error message to see if this pattern applies to the given error.
    # If the error message matches, then compare the found and required lines.
    if self._error_msg not in error_lines[0]:
      return False
    else:
      return (self._found_line_regex.match(error_lines[1]) and
              self._required_line_regex.match(error_lines[2]))


class ChainedPromisePattern(ErrorPattern):
  """Matcher for spurious errors arising from chained promises.  Example code:

  Promise.resolve()
    .then(
        /** @return {!Promise<string>} */
        function() { return Promise.resolve('foo'); })
    .then(
        /** @param {string} s */
        function(s) { console.log(s); });

  The compiler will emit an error that looks like

  ERROR - actual parameter 1 of Promise.prototype.then does not match formal
  parameter
  found   : function (string): undefined
  required: (function (Promise<string>): ?|null|undefined)
  """
  def __init__(self):
    # Matches the initial error message.
    msg = ("ERROR - actual parameter 1 of Promise.prototype.then "
                  "does not match formal parameter")

    # Examples:
    # - function (string): Promise<string>
    # - function ((SomeType|null)): SomeOtherType
    found_pattern = "function\s*\(.*\):\s*.*"

    # Examples:
    # - (function(Promise<string>): ?|null|undefined)
    required_pattern = "\(function\s*\(Promise<.*>\):\s*.*\)"

    ErrorPattern.__init__(self, msg, found_pattern, required_pattern)


class ReturnedPromisePattern(ErrorPattern):
  """Matcher for spurious errors arising from Promised return values.  Example
  code:

  /** @return {!Promise<string>} */
  var getStringAsync = function() {
    /** @return {!Promise<string>} */
    var generateString = function() {return Promise.resolve('foo');};
    return Promise.resolve().then(generateString);
  };

  The compiler will emit an error that looks like

  ERROR - inconsistent return type
  found   : Promise<Promise<string>>
  required: Promise<string>
  """
  def __init__(self):
    # Matches the initial error message.
    msg = "ERROR - inconsistent return type"

    # Example:
    # - Promise<Promise<string>>
    found_pattern = "Promise<Promise<[^<>]*>"

    # Example:
    # - Promise<string>
    required_pattern = "Promise<[^<>]*>"

    ErrorPattern.__init__(self, msg, found_pattern, required_pattern)

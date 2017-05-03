# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Logic for parsing a C/C++ function signature."""


def _FindParameterListParen(name):
  """Finds index of the "(" that denotes the start of a paremeter list."""
  # This loops from left-to-right, but the only reason (I think) that this
  # is necessary (rather than reusing _FindLastCharOutsideOfBrackets), is
  # to capture the outer-most function in the case where classes are nested.
  start_idx = 0
  while True:
    template_balance_count = 0
    paren_balance_count = 0
    while True:
      idx = name.find('(', start_idx)
      if idx == -1:
        return -1
      template_balance_count += (
          name.count('<', start_idx, idx) - name.count('>', start_idx, idx))
      # Special: operators with angle brackets.
      operator_idx = name.find('operator<', start_idx, idx)
      if operator_idx != -1:
        if name[operator_idx + 9] == '<':
          template_balance_count -= 2
        else:
          template_balance_count -= 1
      else:
        operator_idx = name.find('operator>', start_idx, idx)
        if operator_idx != -1:
          if name[operator_idx + 9] == '>':
            template_balance_count += 2
          else:
            template_balance_count += 1

      paren_balance_count += (
          name.count('(', start_idx, idx) - name.count(')', start_idx, idx))
      if template_balance_count == 0 and paren_balance_count == 0:
        # Special case: skip "(anonymous namespace)".
        if -1 != name.find('(anonymous namespace)', idx, idx + 21):
          start_idx = idx + 21
          continue
        # Special case: skip "decltype (...)"
        # Special case: skip "{lambda(PaintOp*)#63}"
        if name[idx - 1] != ' ' and name[idx - 7:idx] != '{lambda':
          return idx
      start_idx = idx + 1
      paren_balance_count += 1


def _FindLastCharOutsideOfBrackets(name, target_char, prev_idx=None):
  """Returns the last index of |target_char| that is not within ()s nor <>s."""
  paren_balance_count = 0
  template_balance_count = 0
  while True:
    idx = name.rfind(target_char, 0, prev_idx)
    if idx == -1:
      return -1
    # It is much faster to use.find() and.count() than to loop over each
    # character.
    template_balance_count += (
        name.count('<', idx, prev_idx) - name.count('>', idx, prev_idx))
    paren_balance_count += (
        name.count('(', idx, prev_idx) - name.count(')', idx, prev_idx))
    if template_balance_count == 0 and paren_balance_count == 0:
      return idx
    prev_idx = idx


def _FindReturnValueSpace(name, paren_idx):
  """Returns the index of the space that comes after the return type."""
  space_idx = paren_idx
  # Special case: const cast operators (see tests).
  if -1 != name.find(' const', paren_idx - 6, paren_idx):
    space_idx = paren_idx - 6
  while True:
    space_idx = _FindLastCharOutsideOfBrackets(name, ' ', space_idx)
    # Special case: "operator new", and "operator<< <template>".
    if -1 == space_idx or (
        -1 == name.find('operator', space_idx - 8, space_idx) and
        -1 == name.find('operator<<', space_idx - 10, space_idx)):
      break
    space_idx -= 8
  return space_idx


def _NormalizeTopLevelLambda(name, space_idx, left_paren_idx):
  # cc::{lambda(PaintOp*)#63}::_FUN() -> cc:{lambda#63}()
  paren_idx = name.index('(', space_idx + 1)
  hash_idx = name.rindex('#', paren_idx)
  return (name[:paren_idx] + name[hash_idx:left_paren_idx - 6] +
          name[left_paren_idx:])


def Parse(name):
  """Extracts a function name from a function signature.

  See unit tests for example signatures.

  Returns:
    A tuple of (name_without_return_type, name_without_return_type_and_params).
  """
  left_paren_idx = _FindParameterListParen(name)

  full_name = name
  if left_paren_idx > 0:
    right_paren_idx = name.rindex(')')
    assert right_paren_idx > left_paren_idx
    space_idx = _FindReturnValueSpace(name, left_paren_idx)
    name_without_attrib = name[space_idx + 1:left_paren_idx]
    # Special case for top-level lamdas.
    if name_without_attrib.endswith('}::_FUN'):
      # Don't use name_without_attrib in here since prior _idx will be off if
      # there was a return value.
      name = _NormalizeTopLevelLambda(name, space_idx, left_paren_idx)
      return Parse(name)

    full_name = name[space_idx + 1:]
    name = name_without_attrib + name[right_paren_idx + 1:]

  return full_name, name

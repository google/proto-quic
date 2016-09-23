# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

_API_UTIL_NAMESPACE = 'json_schema_compiler::util'


class UtilCCHelper(object):
  """A util class that generates code that uses
  tools/json_schema_compiler/util.cc.
  """
  def __init__(self, type_manager):
    self._type_manager = type_manager

  def PopulateArrayFromListFunction(self, optional):
    """Returns the function to turn a list into a vector.
    """
    populate_list_fn = ('PopulateOptionalArrayFromList' if optional
                            else 'PopulateArrayFromList')
    return ('%s::%s') % (_API_UTIL_NAMESPACE, populate_list_fn)

  def CreateValueFromArray(self, src, optional):
    """Generates code to create a scoped_pt<Value> from the array at src.

    |src| The variable to convert, either a vector or std::unique_ptr<vector>.
    |optional| Whether |type_| was optional. Optional types are pointers so
        must be treated differently.
    """
    if optional:
      name = 'CreateValueFromOptionalArray'
    else:
      name = 'CreateValueFromArray'
    return '%s::%s(%s)' % (_API_UTIL_NAMESPACE, name, src)

  def GetIncludePath(self):
    return '#include "tools/json_schema_compiler/util.h"'

  def GetValueTypeString(self, value, is_ptr=False):
    call = '.GetType()'
    if is_ptr:
      call = '->GetType()'
    return 'std::string(base::Value::GetTypeName(%s%s))' % (value, call)

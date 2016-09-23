#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Adaptation of the extern.tclib classes for our needs.
'''


import re
import types

from grit import exception
from grit import lazy_re
import grit.extern.tclib


# Matches whitespace sequences which can be folded into a single whitespace
# character.  This matches single characters so that non-spaces are replaced
# with spaces.
_FOLD_WHITESPACE = re.compile(r'\s+')


def Identity(i):
  return i


class BaseMessage(object):
  '''Base class with methods shared by Message and Translation.
  '''

  def __init__(self, text='', placeholders=[], description='', meaning=''):
    self.parts = []
    self.placeholders = []
    self.meaning = meaning
    self.dirty = True  # True if self.id is (or might be) wrong
    self.id = 0
    self.SetDescription(description)

    if text != '':
      if not placeholders or placeholders == []:
        self.AppendText(text)
      else:
        tag_map = {}
        for placeholder in placeholders:
          tag_map[placeholder.GetPresentation()] = [placeholder, 0]
        # This creates a regexp like '(TAG1|TAG2|TAG3)'.
        # The tags have to be sorted in order of decreasing length, so that
        # longer tags are substituted before shorter tags that happen to be
        # substrings of the longer tag.
        # E.g. "EXAMPLE_FOO_NAME" must be matched before "EXAMPLE_FOO",
        # otherwise "EXAMPLE_FOO" splits "EXAMPLE_FOO_NAME" too.
        tags = tag_map.keys()
        tags.sort(cmp=lambda x,y: len(x) - len(y) or cmp(x, y), reverse=True)
        tag_re = '(' + '|'.join(tags) + ')'
        chunked_text = re.split(tag_re, text)
        for chunk in chunked_text:
          if chunk: # ignore empty chunk
            if tag_map.has_key(chunk):
              self.AppendPlaceholder(tag_map[chunk][0])
              tag_map[chunk][1] += 1 # increase placeholder use count
            else:
              self.AppendText(chunk)
        for key in tag_map.keys():
          assert tag_map[key][1] != 0

  def GetRealContent(self, escaping_function=Identity):
    '''Returns the original content, i.e. what your application and users
    will see.

    Specify a function to escape each translateable bit, if you like.
    '''
    bits = []
    for item in self.parts:
      if isinstance(item, types.StringTypes):
        bits.append(escaping_function(item))
      else:
        bits.append(item.GetOriginal())
    return ''.join(bits)

  def GetPresentableContent(self):
    presentable_content = []
    for part in self.parts:
      if isinstance(part, Placeholder):
        presentable_content.append(part.GetPresentation())
      else:
        presentable_content.append(part)
    return ''.join(presentable_content)

  def AppendPlaceholder(self, placeholder):
    assert isinstance(placeholder, Placeholder)
    dup = False
    for other in self.GetPlaceholders():
      if other.presentation == placeholder.presentation:
        assert other.original == placeholder.original
        dup = True

    if not dup:
      self.placeholders.append(placeholder)
    self.parts.append(placeholder)
    self.dirty = True

  def AppendText(self, text):
    assert isinstance(text, types.StringTypes)
    assert text != ''

    self.parts.append(text)
    self.dirty = True

  def GetContent(self):
    '''Returns the parts of the message.  You may modify parts if you wish.
    Note that you must not call GetId() on this object until you have finished
    modifying the contents.
    '''
    self.dirty = True  # user might modify content
    return self.parts

  def GetDescription(self):
    return self.description

  def SetDescription(self, description):
    self.description = _FOLD_WHITESPACE.sub(' ', description)

  def GetMeaning(self):
    return self.meaning

  def GetId(self):
    if self.dirty:
      self.id = self.GenerateId()
      self.dirty = False
    return self.id

  def GenerateId(self):
    # Must use a UTF-8 encoded version of the presentable content, along with
    # the meaning attribute, to match the TC.
    return grit.extern.tclib.GenerateMessageId(
      self.GetPresentableContent().encode('utf-8'), self.meaning)

  def GetPlaceholders(self):
    return self.placeholders

  def FillTclibBaseMessage(self, msg):
    msg.SetDescription(self.description.encode('utf-8'))

    for part in self.parts:
      if isinstance(part, Placeholder):
        ph = grit.extern.tclib.Placeholder(
          part.presentation.encode('utf-8'),
          part.original.encode('utf-8'),
          part.example.encode('utf-8'))
        msg.AppendPlaceholder(ph)
      else:
        msg.AppendText(part.encode('utf-8'))


class Message(BaseMessage):
  '''A message.'''

  def __init__(self, text='', placeholders=[], description='', meaning='',
               assigned_id=None):
    super(Message, self).__init__(text, placeholders, description, meaning)
    self.assigned_id = assigned_id

  def ToTclibMessage(self):
    msg = grit.extern.tclib.Message('utf-8', meaning=self.meaning)
    self.FillTclibBaseMessage(msg)
    return msg

  def GetId(self):
    '''Use the assigned id if we have one.'''
    if self.assigned_id:
      return self.assigned_id

    return super(Message, self).GetId()

  def HasAssignedId(self):
    '''Returns True if this message has an assigned id.'''
    return bool(self.assigned_id)


class Translation(BaseMessage):
  '''A translation.'''

  def __init__(self, text='', id='', placeholders=[], description='', meaning=''):
    super(Translation, self).__init__(text, placeholders, description, meaning)
    self.id = id

  def GetId(self):
    assert id != '', "ID has not been set."
    return self.id

  def SetId(self, id):
    self.id = id

  def ToTclibMessage(self):
    msg = grit.extern.tclib.Message(
      'utf-8', id=self.id, meaning=self.meaning)
    self.FillTclibBaseMessage(msg)
    return msg


class Placeholder(grit.extern.tclib.Placeholder):
  '''Modifies constructor to accept a Unicode string
  '''

  # Must match placeholder presentation names
  _NAME_RE = lazy_re.compile('^[A-Za-z0-9_]+$')

  def __init__(self, presentation, original, example):
    '''Creates a new placeholder.

    Args:
      presentation: 'USERNAME'
      original: '%s'
      example: 'Joi'
    '''
    assert presentation != ''
    assert original != ''
    assert example != ''
    if not self._NAME_RE.match(presentation):
      raise exception.InvalidPlaceholderName(presentation)
    self.presentation = presentation
    self.original = original
    self.example = example

  def GetPresentation(self):
    return self.presentation

  def GetOriginal(self):
    return self.original

  def GetExample(self):
    return self.example



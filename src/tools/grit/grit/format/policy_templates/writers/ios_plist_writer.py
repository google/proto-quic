#!/usr/bin/env python
# Copyright (c) 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import base64

from xml.dom import minidom
from grit.format.policy_templates.writers import plist_writer


# This writer outputs a Property List with an example for each of the policies
# supported on iOS. This plist can be pushed to Chrome on iOS via the MDM API
# introduced in iOS 7.

CHROME_POLICY_COMMENT = '''\
 ChromePolicy is the preferred key to configure Chrome.
         Each of the keys in this <dict> configures a Chrome policy.
         All of the Chrome policies are configured with an example
         value below.
         Note that it's not necessary to configure all of them. '''

ENCODED_CHROME_POLICY_COMMENT = '''\
 EncodedChromePolicy contains a Property List file, encoded in Base64,
         which contains the same policies that can go in ChromePolicy.
         This key can be used by vendors that restrict the app configuration
         types to strings.
         The value of this string can be validated by running these
         commands in Mac OS X:

         # (first, copy-paste the string into a file named "policy.plist")
         # base64 -D < policy.plist > decoded_policy.plist
         # plutil -lint decoded_policy.plist

         plutil should indicate that decoded_policy.plist is valid,
         otherwise Chrome will reject the encoded string too.

         This command can be used to pretty-print the plist file:

         # plutil -convert xml1 decoded_policy.plist

         Note that <ChromePolicy> is the preferred key to configure Chrome.
         If <ChromePolicy> is present then <EncodedChromePolicy> is ignored. '''

def GetWriter(config):
  '''Factory method for creating IOSPlistWriter objects.
  See the constructor of TemplateWriter for description of
  arguments.
  '''
  return IOSPlistWriter(['ios'], config)


class IOSPlistWriter(plist_writer.PListWriter):
  '''Class for generating policy templates in the iOS plist format.
  It is used by PolicyTemplateGenerator to write plist files.
  '''

  # Overridden.
  def IsPolicySupported(self, policy):
    # Output examples only for policies that are supported on iOS.
    for support_on in policy['supported_on']:
      if ('ios' in support_on['platforms'] and
          support_on['until_version'] == '' and
          super(IOSPlistWriter, self).IsPolicySupported(policy)):
        return True
    return False

  def _WriteValue(self, parent, value):
    if type(value) == bool:
      self.AddElement(parent, 'true' if value else 'false')
    elif type(value) == int:
      self.AddElement(parent, 'integer', {}, str(value))
    elif type(value) == str:
      self.AddElement(parent, 'string', {}, value)
    elif type(value) == list:
      array = self.AddElement(parent, 'array')
      for element in value:
        self._WriteValue(array, element)
    elif type(value) == dict:
      dic = self.AddElement(parent, 'dict')
      for k, v in sorted(value.iteritems()):
        self.AddElement(dic, 'key', {}, k)
        self._WriteValue(dic, v)
    else:
      raise ValueError('Unsupported type in example value: ' + type(value))

  # Overridden.
  def WritePolicy(self, policy):
    for dict in [self._dict, self._encoded_dict]:
      self.AddElement(dict, 'key', {}, policy['name'])
      self._WriteValue(dict, policy['example_value'])

  # Overridden.
  # |self._plist| is created in super.Init().
  def BeginTemplate(self):
    self._plist.attributes['version'] = '1.0'
    self._root_dict = self.AddElement(self._plist, 'dict')
    self.AddComment(self._root_dict, CHROME_POLICY_COMMENT)
    if self._GetChromiumVersionString() is not None:
      self.AddComment(self._root_dict, ' ' + self.config['build'] + \
          ' version: ' + self._GetChromiumVersionString() + ' ')
    self._dict = self._AddKeyValuePair(self._root_dict, 'ChromePolicy', 'dict')

    self._encoded_plist.attributes['version'] = '1.0'
    self._encoded_dict = self.AddElement(self._encoded_plist, 'dict')

  # Overridden.
  def EndTemplate(self):
    # Add the "EncodedChromePolicy" entry.
    encoded = base64.b64encode(self._encoded_doc.toxml())
    self.AddComment(self._root_dict, ENCODED_CHROME_POLICY_COMMENT)
    self._AddStringKeyValuePair(self._root_dict, 'EncodedChromePolicy', encoded)

  # Overridden.
  def Init(self):
    super(IOSPlistWriter, self).Init()
    # Create a secondary DOM for the EncodedChromePolicy Plist, which will be
    # serialized and encoded in EndTemplate.
    self._encoded_doc = self.CreatePlistDocument()
    self._encoded_plist = self._encoded_doc.documentElement

  # Overridden.
  def GetTemplateText(self):
    return self.ToPrettyXml(self._doc, encoding='UTF-8')

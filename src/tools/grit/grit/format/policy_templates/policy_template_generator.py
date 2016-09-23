#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import copy


class PolicyTemplateGenerator:
  '''Generates template text for a particular platform.

  This class is used to traverse a JSON structure from a .json template
  definition metafile and merge GUI message string definitions that come
  from a .grd resource tree onto it. After this, it can be used to output
  this data to policy template files using TemplateWriter objects.
  '''

  def _ImportMessage(self, msg_txt):
    msg_txt = msg_txt.decode('utf-8')
    # Replace the placeholder of app name.
    msg_txt = msg_txt.replace('$1', self._config['app_name'])
    msg_txt = msg_txt.replace('$2', self._config['os_name'])
    msg_txt = msg_txt.replace('$3', self._config['frame_name'])
    # Strip spaces and escape newlines.
    lines = msg_txt.split('\n')
    lines = [line.strip() for line in lines]
    return "\n".join(lines)

  def __init__(self, config, policy_data):
    '''Initializes this object with all the data necessary to output a
    policy template.

    Args:
      messages: An identifier to string dictionary of all the localized
        messages that might appear in the policy template.
      policy_definitions: The list of defined policies and groups, as
        parsed from the policy metafile. Note that this list is passed by
        reference and its contents are modified.
        See chrome/app/policy.policy_templates.json for description and
        content.
    '''
    # List of all the policies:
    self._policy_data = copy.deepcopy(policy_data)
    # Localized messages to be inserted to the policy_definitions structure:
    self._messages = self._policy_data['messages']
    self._config = config
    for key in self._messages.keys():
      self._messages[key]['text'] = self._ImportMessage(
          self._messages[key]['text'])
    self._policy_definitions = self._policy_data['policy_definitions']
    self._ProcessPolicyList(self._policy_definitions)

  def _ProcessSupportedOn(self, supported_on):
    '''Parses and converts the string items of the list of supported platforms
    into dictionaries.

    Args:
      supported_on: The list of supported platforms. E.g.:
        ['chrome.win:8-10', 'chrome_frame:10-']

    Returns:
      supported_on: The list with its items converted to dictionaries. E.g.:
      [{
        'product': 'chrome',
        'platforms': 'win',
        'since_version': '8',
        'until_version': '10'
      }, {
        'product': 'chrome_frame',
        'platforms': 'win',
        'since_version': '10',
        'until_version': ''
      }]
    '''
    result = []
    for supported_on_item in supported_on:
      product_platform_part, version_part = supported_on_item.split(':')

      if '.' in product_platform_part:
        product, platform = product_platform_part.split('.')
        if platform == '*':
          # e.g.: 'chrome.*:8-10'
          platforms = ['linux', 'mac', 'win']
        else:
          # e.g.: 'chrome.win:-10'
          platforms = [platform]
      else:
        # e.g.: 'chrome_frame:7-'
        product, platform = {
          'android':         ('chrome',        'android'),
          'webview_android': ('webview',       'android'),
          'chrome_os':       ('chrome_os',     'chrome_os'),
          'chrome_frame':    ('chrome_frame',  'win'),
          'ios':             ('chrome',        'ios'),
        }[product_platform_part]
        platforms = [platform]
      since_version, until_version = version_part.split('-')
      result.append({
        'product': product,
        'platforms': platforms,
        'since_version': since_version,
        'until_version': until_version
      })
    return result

  def _ProcessPolicy(self, policy):
    '''Processes localized message strings in a policy or a group.
     Also breaks up the content of 'supported_on' attribute into a list.

    Args:
      policy: The data structure of the policy or group, that will get message
        strings here.
    '''
    policy['desc'] = self._ImportMessage(policy['desc'])
    policy['caption'] = self._ImportMessage(policy['caption'])
    if 'label' in policy:
      policy['label'] = self._ImportMessage(policy['label'])
    if 'arc_support' in policy:
      policy['arc_support'] = self._ImportMessage(policy['arc_support'])


    if policy['type'] == 'group':
      self._ProcessPolicyList(policy['policies'])
    elif policy['type'] in ('string-enum', 'int-enum', 'string-enum-list'):
      # Iterate through all the items of an enum-type policy, and add captions.
      for item in policy['items']:
        item['caption'] = self._ImportMessage(item['caption'])
    if policy['type'] != 'group':
      if not 'label' in policy:
        # If 'label' is not specified, then it defaults to 'caption':
        policy['label'] = policy['caption']
      policy['supported_on'] = self._ProcessSupportedOn(policy['supported_on'])

  def _ProcessPolicyList(self, policy_list):
    '''Adds localized message strings to each item in a list of policies and
    groups. Also breaks up the content of 'supported_on' attributes into lists
    of dictionaries.

    Args:
      policy_list: A list of policies and groups. Message strings will be added
        for each item and to their child items, recursively.
    '''
    for policy in policy_list:
      self._ProcessPolicy(policy)

  def GetTemplateText(self, template_writer):
    '''Generates the text of the template from the arguments given
    to the constructor, using a given TemplateWriter.

    Args:
      template_writer: An object implementing TemplateWriter. Its methods
        are called here for each item of self._policy_groups.

    Returns:
      The text of the generated template.
    '''
    return template_writer.WriteTemplate(self._policy_data)

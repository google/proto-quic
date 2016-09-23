#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class TemplateWriter(object):
  '''Abstract base class for writing policy templates in various formats.
  The methods of this class will be called by PolicyTemplateGenerator.
  '''

  def __init__(self, platforms, config):
    '''Initializes a TemplateWriter object.

    Args:
      platforms: List of platforms for which this writer can write policies.
      config: A dictionary of information required to generate the template.
        It contains some key-value pairs, including the following examples:
          'build': 'chrome' or 'chromium'
          'branding': 'Google Chrome' or 'Chromium'
          'mac_bundle_id': The Mac bundle id of Chrome. (Only set when building
            for Mac.)
      messages: List of all the message strings from the grd file. Most of them
        are also present in the policy data structures that are passed to
        methods. That is the preferred way of accessing them, this should only
        be used in exceptional cases. An example for its use is the
        IDS_POLICY_WIN_SUPPORTED_WINXPSP2 message in ADM files, because that
        cannot be associated with any policy or group.
    '''
    self.platforms = platforms
    self.config = config

  def IsDeprecatedPolicySupported(self, policy):
    '''Checks if the given deprecated policy is supported by the writer.

    Args:
      policy: The dictionary of the policy.

    Returns:
      True if the writer chooses to include the deprecated 'policy' in its
      output.
    '''
    return False

  def IsFuturePolicySupported(self, policy):
    '''Checks if the given future policy is supported by the writer.

    Args:
      policy: The dictionary of the policy.

    Returns:
      True if the writer chooses to include the deprecated 'policy' in its
      output.
    '''
    return False

  def IsPolicySupported(self, policy):
    '''Checks if the given policy is supported by the writer.
    In other words, the set of platforms supported by the writer
    has a common subset with the set of platforms that support
    the policy.

    Args:
      policy: The dictionary of the policy.

    Returns:
      True if the writer chooses to include 'policy' in its output.
    '''
    if ('deprecated' in policy and policy['deprecated'] is True and
        not self.IsDeprecatedPolicySupported(policy)):
      return False

    if ('future' in policy and policy['future'] is True and
        not self.IsFuturePolicySupported(policy)):
      return False

    if '*' in self.platforms:
      # Currently chrome_os is only catched here.
      return True
    for supported_on in policy['supported_on']:
      for supported_on_platform in supported_on['platforms']:
        if supported_on_platform in self.platforms:
          return True
    return False

  def CanBeRecommended(self, policy):
    '''Checks if the given policy can be recommended.'''
    return policy.get('features', {}).get('can_be_recommended', False)

  def CanBeMandatory(self, policy):
    '''Checks if the given policy can be mandatory.'''
    return policy.get('features', {}).get('can_be_mandatory', True)

  def IsPolicySupportedOnPlatform(self, policy, platform, product=None):
    '''Checks if |policy| is supported on |product| for |platform|. If not
    specified, only the platform support is checked.

    Args:
      policy: The dictionary of the policy.
      platform: The platform to check; one of 'win', 'mac', 'linux' or
        'chrome_os'.
      product: Optional product to check; one of 'chrome', 'chrome_frame',
        'chrome_os', 'webview'
    '''
    is_supported = lambda x: (platform in x['platforms'] and
                             (not product or product in x['product']))

    return any(filter(is_supported, policy['supported_on']))

  def _GetChromiumVersionString(self):
    '''Returns the Chromium version string stored in the environment variable
    version (if it is set).

    Returns: The Chromium version string or None if it has not been set.'''

    if 'version' in self.config:
      return self.config['version']

  def _GetPoliciesForWriter(self, group):
    '''Filters the list of policies in the passed group that are supported by
    the writer.

    Args:
      group: The dictionary of the policy group.

    Returns: The list of policies of the policy group that are compatible
      with the writer.
    '''
    if not 'policies' in group:
      return []
    result = []
    for policy in group['policies']:
      if self.IsPolicySupported(policy):
        result.append(policy)
    return result

  def Init(self):
    '''Initializes the writer. If the WriteTemplate method is overridden, then
    this method must be called as first step of each template generation
    process.
    '''
    pass

  def WriteTemplate(self, template):
    '''Writes the given template definition.

    Args:
      template: Template definition to write.

    Returns:
      Generated output for the passed template definition.
    '''
    self.messages = template['messages']
    self.Init()
    template['policy_definitions'] = \
        self.PreprocessPolicies(template['policy_definitions'])
    self.BeginTemplate()
    for policy in template['policy_definitions']:
      if policy['type'] == 'group':
        child_policies = self._GetPoliciesForWriter(policy)
        child_recommended_policies = filter(self.CanBeRecommended,
                                            child_policies)
        if child_policies:
          # Only write nonempty groups.
          self.BeginPolicyGroup(policy)
          for child_policy in child_policies:
            # Nesting of groups is currently not supported.
            self.WritePolicy(child_policy)
          self.EndPolicyGroup()
        if child_recommended_policies:
          self.BeginRecommendedPolicyGroup(policy)
          for child_policy in child_recommended_policies:
            self.WriteRecommendedPolicy(child_policy)
          self.EndRecommendedPolicyGroup()
      elif self.IsPolicySupported(policy):
        self.WritePolicy(policy)
        if self.CanBeRecommended(policy):
          self.WriteRecommendedPolicy(policy)
    self.EndTemplate()

    return self.GetTemplateText()

  def PreprocessPolicies(self, policy_list):
    '''Preprocesses a list of policies according to a given writer's needs.
    Preprocessing steps include sorting policies and stripping unneeded
    information such as groups (for writers that ignore them).
    Subclasses are encouraged to override this method, overriding
    implementations may call one of the provided specialized implementations.
    The default behaviour is to use SortPoliciesGroupsFirst().

    Args:
      policy_list: A list containing the policies to sort.

    Returns:
      The sorted policy list.
    '''
    return self.SortPoliciesGroupsFirst(policy_list)

  def WritePolicy(self, policy):
    '''Appends the template text corresponding to a policy into the
    internal buffer.

    Args:
      policy: The policy as it is found in the JSON file.
    '''
    raise NotImplementedError()

  def WriteComment(self, comment):
    '''Appends the comment to the internal buffer.

      comment: The comment to be added.
    '''
    raise NotImplementedError()

  def WriteRecommendedPolicy(self, policy):
    '''Appends the template text corresponding to a recommended policy into the
    internal buffer.

    Args:
      policy: The recommended policy as it is found in the JSON file.
    '''
    # TODO
    #raise NotImplementedError()
    pass

  def BeginPolicyGroup(self, group):
    '''Appends the template text corresponding to the beginning of a
    policy group into the internal buffer.

    Args:
      group: The policy group as it is found in the JSON file.
    '''
    pass

  def EndPolicyGroup(self):
    '''Appends the template text corresponding to the end of a
    policy group into the internal buffer.
    '''
    pass

  def BeginRecommendedPolicyGroup(self, group):
    '''Appends the template text corresponding to the beginning of a recommended
    policy group into the internal buffer.

    Args:
      group: The recommended policy group as it is found in the JSON file.
    '''
    pass

  def EndRecommendedPolicyGroup(self):
    '''Appends the template text corresponding to the end of a recommended
    policy group into the internal buffer.
    '''
    pass

  def BeginTemplate(self):
    '''Appends the text corresponding to the beginning of the whole
    template into the internal buffer.
    '''
    raise NotImplementedError()

  def EndTemplate(self):
    '''Appends the text corresponding to the end of the whole
    template into the internal buffer.
    '''
    pass

  def GetTemplateText(self):
    '''Gets the content of the internal template buffer.

    Returns:
      The generated template from the the internal buffer as a string.
    '''
    raise NotImplementedError()

  def SortPoliciesGroupsFirst(self, policy_list):
    '''Sorts a list of policies alphabetically. The order is the
    following: first groups alphabetically by caption, then other policies
    alphabetically by name. The order of policies inside groups is unchanged.

    Args:
      policy_list: The list of policies to sort. Sub-lists in groups will not
        be sorted.
    '''
    policy_list.sort(key=self.GetPolicySortingKeyGroupsFirst)
    return policy_list

  def FlattenGroupsAndSortPolicies(self, policy_list, sorting_key=None):
    '''Sorts a list of policies according to |sorting_key|, defaulting
    to alphabetical sorting if no key is given. If |policy_list| contains
    policies with type="group", it is flattened first, i.e. any groups' contents
    are inserted into the list as first-class elements and the groups are then
    removed.
    '''
    new_list = []
    for policy in policy_list:
      if policy['type'] == 'group':
        for grouped_policy in policy['policies']:
          new_list.append(grouped_policy)
      else:
        new_list.append(policy)
    if sorting_key == None:
      sorting_key = self.GetPolicySortingKeyName
    new_list.sort(key=sorting_key)
    return new_list

  def GetPolicySortingKeyName(self, policy):
    return policy['name']

  def GetPolicySortingKeyGroupsFirst(self, policy):
    '''Extracts a sorting key from a policy. These keys can be used for
    list.sort() methods to sort policies.
    See TemplateWriter.SortPolicies for usage.
    '''
    is_group = policy['type'] == 'group'
    if is_group:
      # Groups are sorted by caption.
      str_key = policy['caption']
    else:
      # Regular policies are sorted by name.
      str_key = policy['name']
    # Groups come before regular policies.
    return (not is_group, str_key)

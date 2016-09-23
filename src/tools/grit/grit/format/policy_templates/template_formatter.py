#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import sys
from functools import partial

from grit.format.policy_templates import policy_template_generator
from grit.format.policy_templates import writer_configuration
from grit.node import misc
from grit.node import structure


def GetFormatter(type):
  return partial(_TemplateFormatter,
                 'grit.format.policy_templates.writers.%s_writer' % type)


def _TemplateFormatter(writer_module_name, root, lang, output_dir):
  '''Creates a template file corresponding to an <output> node of the grit
  tree.

  More precisely, processes the whole grit tree for a given <output> node whose
  type is one of adm, plist, plist_strings, admx, adml, doc, json, reg.
  The result of processing is a policy template file with the given type and
  language of the <output> node. This function does the interfacing with
  grit, but the actual template-generating work is done in
  policy_template_generator.PolicyTemplateGenerator.

  Args:
    writer_name: A string identifying the TemplateWriter subclass used
      for generating the output.
    root: the <grit> root node of the grit tree.
    lang: the language of outputted text, e.g.: 'en'
    output_dir: The output directory, currently unused here.

  Yields the text of the template file.
  '''
  __import__(writer_module_name)
  writer_module = sys.modules[writer_module_name]
  config = writer_configuration.GetConfigurationForBuild(root.defines)
  policy_data = _ParseGritNodes(root, lang)
  policy_generator = \
      policy_template_generator.PolicyTemplateGenerator(config, policy_data)
  writer = writer_module.GetWriter(config)
  yield policy_generator.GetTemplateText(writer)


def _ParseGritNodes(root, lang):
  '''Collects the necessary information from the grit tree:
  the message strings and the policy definitions.

  Args:
    root: The root of the grit tree.
    lang: the language of outputted text, e.g.: 'en'

  Returns:
    Policy data.
  '''
  policy_data = None
  for item in root.ActiveDescendants():
    with item:
      if (isinstance(item, structure.StructureNode) and
          item.attrs['type'] == 'policy_template_metafile'):
        assert policy_data is None
        json_text = item.gatherer.Translate(
            lang,
            pseudo_if_not_available=item.PseudoIsAllowed(),
            fallback_to_english=item.ShouldFallbackToEnglish())
        policy_data = eval(json_text)
  return policy_data

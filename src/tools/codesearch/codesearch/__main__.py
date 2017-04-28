# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Command line interface to Chromium Code Search.

Currently emits JSON formatted responses from the Chromium CodeSearch backend at
https://cs.chromium.org.
"""

from __future__ import absolute_import

import os
import argparse
import sys
import json
import logging

from codesearch import CodeSearch, CompoundRequest, \
        CodeSearchProtoJsonSymbolizedEncoder, CodeSearchProtoJsonEncoder, \
        XrefSearchRequest, SearchRequest, FileInfoRequest, DirInfoRequest, \
        CallGraphRequest


def print_result(results, args):
  if args.pretty:
    print json.dumps(
        results,
        indent=4,
        ensure_ascii=True,
        cls=CodeSearchProtoJsonSymbolizedEncoder)
  else:
    print json.dumps(results, cls=CodeSearchProtoJsonEncoder)


def get_signature(cs, args):
  if args.signature:
    return args.signature

  if not (args.path and args.word):
    print('Both PATH and WORD must be specified')
    sys.exit(2)

  return cs.GetSignatureForSymbol(args.path, args.word)


def setup_logging(cs, args):
  if args.loglevel:
    if args.loglevel == 'info':
      level = logging.INFO
    else:
      level = logging.DEBUG
    cs.GetLogger().setLevel(level)
    logging.basicConfig()


parser = argparse.ArgumentParser(description=__doc__)

subcommands = parser.add_subparsers(help='Subcommands')

path_specifiers = argparse.ArgumentParser(add_help=False)
path_specifiers.add_argument('path', help='Path to file.', metavar='PATH')

signature_specifiers = argparse.ArgumentParser(
    description='Used to specify a target for the query.', add_help=False)

subgroup = signature_specifiers.add_argument_group(
    'arguments for specifying a target')
subgroup.add_argument('-p', '--path', help='Path to file.')
subgroup.add_argument(
    '-w',
    '--word',
    help=
    '''The word to search for in the file denoted by the path argument. You must
    also specify -p''')
subgroup.add_argument(
    '-s',
    '--signature',
    help='''A signature provided from a previous search. No -p or -w arguments
    required.''')

common_args = argparse.ArgumentParser(
    description='Common options', add_help=False)
common_args.add_argument(
    '--pretty',
    help='Whether to pretty print the resulting JSON',
    default=True,
    action='store_true')
common_args.add_argument(
    '--loglevel', '-l', help='Log level', choices=['info', 'debug'])
common_args.add_argument('--cache', '-C', help='Cache directory')

# sig
signature_command = subcommands.add_parser(
    'sig', help='Query signature', parents=[signature_specifiers, common_args])
signature_command.set_defaults(
    func=lambda cs, a: {'signature': get_signature(cs, a)})

# xrefs
xrefs_command = subcommands.add_parser(
    'xrefs',
    help='Query cross-references',
    parents=[signature_specifiers, common_args])
xrefs_command.set_defaults(func=lambda cs, a: cs.SendRequestToServer(
    CompoundRequest(
        xref_search_request=[
            XrefSearchRequest(
                query=get_signature(cs, a),
                file_spec=cs.GetFileSpec('.'),
                max_num_results=100
            )
        ]
    )))

# callers
callers_command = subcommands.add_parser(
    'callers',
    help='Query callers for a signature',
    parents=[signature_specifiers, common_args])
callers_command.set_defaults(
    func=lambda cs, a: cs.SendRequestToServer(
        CompoundRequest(
            call_graph_request=[
                CallGraphRequest(
                    signature=get_signature(cs, a),
                    file_spec=cs.GetFileSpec('.'),
                    max_num_results=100)
            ]
        )))

# annot
annotate_command = subcommands.add_parser(
    'annot',
    help='Get annotations for file',
    parents=[path_specifiers, common_args])
annotate_command.add_argument(
    '--type',
    '-t',
    help='Type',
    action='append',
    choices=['LINK_TO_DEFINITION', 'LINK_TO_URL', 'XREF_SIGNATURE'],
    default=[])
annotate_command.set_defaults(
    func=lambda cs, a: cs.GetAnnotationsForFile(
        a.path, [{'id': x} for x in a.type]))

# file_info
file_info_command = subcommands.add_parser(
    'fileinfo', help='Get file info', parents=[path_specifiers, common_args])
file_info_command.add_argument(
    '--outline',
    '-o',
    help='Get outlining metadata.',
    default=False,
    action='store_true')
file_info_command.add_argument(
    '--html', '-H', help='Get HTML.', default=False, action='store_true')
file_info_command.add_argument(
    '--folding',
    '-f',
    help='Get folding metadata.',
    default=False,
    action='store_true')
file_info_command.set_defaults(
    func=lambda cs, a: cs.SendRequestToServer(
        CompoundRequest(
            file_info_request=[
                FileInfoRequest(
                    file_spec=cs.GetFileSpec(a.path),
                    fetch_html_content=a.html,
                    fetch_outline=a.outline,
                    fetch_folding=a.folding,
                    fetch_generated_from=False
                )
            ]
        )))

# dir_info
dir_info_command = subcommands.add_parser(
    'dirinfo',
    help='Get directory info',
    parents=[path_specifiers, common_args])
dir_info_command.set_defaults(
    func=lambda cs, a: cs.SendRequestToServer(
        CompoundRequest(
            dir_info_request=[
                DirInfoRequest(
                    file_spec=cs.GetFileSpec(a.path)
                )
            ]
        )))

# search
search_command = subcommands.add_parser(
    'q', help='Search', parents=[common_args])
search_command.add_argument('query', help='Search terms.', metavar='QUERY')
search_command.add_argument(
    '--max_results',
    '-N',
    help='Maximum number of results to return.',
    type=int,
    default=50)
search_command.add_argument(
    '--snippets', '-S', help='Include snippets.', action='store_true')
search_command.add_argument(
    '--decorate',
    '-D',
    help='Decorate snippets with syntactic hints',
    action='store_true')
search_command.add_argument(
    '--context',
    '-U',
    help='Lines of context to inclued in snippets.',
    type=int,
    default=3)
search_command.set_defaults(
    func=lambda cs, a: cs.SendRequestToServer(
        CompoundRequest(
            search_request=[
                SearchRequest(
                    query=a.query,
                    return_snippets=(a.snippets or a.decorate),
                    return_decorated_snippets=a.decorate,
                    max_num_results=a.max_results,
                    lines_context=a.context
                )
            ]
        )))

# status
status_command = subcommands.add_parser(
    'status', help='CodeSearch server status', parents=[common_args])
status_command.set_defaults(
    func=
    lambda cs, a: cs.SendRequestToServer(CompoundRequest(status_request=[{}])))

arguments = parser.parse_args()

try:
  codesearch_instance = CodeSearch(
      a_path_inside_source_dir=os.getcwd(),
      cache_dir=arguments.cache if arguments.cache else None)
  setup_logging(codesearch_instance, arguments)
  print_result(arguments.func(codesearch_instance, arguments), arguments)
finally:
  codesearch_instance.TeardownCache()

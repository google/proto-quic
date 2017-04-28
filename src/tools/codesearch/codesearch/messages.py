# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import sys


class CodeSearchProtoJsonEncoder(json.JSONEncoder):

  def default(self, o):
    if isinstance(o, Message):
      return o.__dict__
    return o


class CodeSearchProtoJsonSymbolizedEncoder(json.JSONEncoder):

  def default(self, o):
    if isinstance(o, Message):
      rv = {}
      desc = o.__class__.DESCRIPTOR
      for k, v in o.__dict__.iteritems():
        if k in desc and not isinstance(desc[k], list) and issubclass(
            desc[k], Message) and desc[k].IsEnum():
          rv[k] = desc[k].ToSymbol(v)
        else:
          rv[k] = v
      return rv
    return o


class Message(object):

  class PARENT_TYPE:
    pass

  def AsQueryString(self):
    values = []
    for k, v in self.__dict__.iteritems():
      values.extend(Message.ToQueryString(k, v))
    return values

  @staticmethod
  def ToQueryString(k, o):
    if o is None:
      return []
    if isinstance(o, Message):
      return [(k, 'b')] + o.AsQueryString() + [(k, 'e')]
    if isinstance(o, bool):
      return [(k, 'true' if o else 'false')]
    if isinstance(o, list):
      values = []
      for v in o:
        values.extend(Message.ToQueryString(k, v))
      return values
    return [(k, str(o))]

  @staticmethod
  def Coerce(source, target_type, parent_class=None):
    if isinstance(target_type, list):
      assert isinstance(source, list)
      assert len(target_type) == 1
      target_type = target_type[0]

      return [Message.Coerce(x, target_type, parent_class) for x in source]

    if target_type == Message.PARENT_TYPE:

      assert parent_class is not None

      return Message.Coerce(source, parent_class, parent_class)

    if issubclass(target_type, Message):
      if isinstance(source, target_type):
        return source

      typespec = target_type.DESCRIPTOR
      if isinstance(typespec, dict):
        assert isinstance(
            source, dict), 'Source is not a dictionary: %s; Mapping to %s' % (
                source, target_type)
        dest = target_type()
        for k, v in source.iteritems():
          if k in typespec:
            dest.__dict__[k] = Message.Coerce(v, typespec[k], target_type)
          else:
            dest.__dict__[k] = v
        return dest
      if typespec is None:
        assert isinstance(source, dict)
        m = Message()
        m.__dict__ = source.copy()
        return m
      if sys.version_info[0] == 2:
        if typespec != str and isinstance(source, basestring) and hasattr(
            target_type, source):
          return typespec(getattr(target_type, source))
      else:
        if typespec != str and isinstance(source, str) and hasattr(
            target_type, source):
          return typespec(getattr(target_type, source))
      return typespec(source)
    return target_type(source)

  @classmethod
  def IsEnum(cls):
    return not isinstance(cls.DESCRIPTOR, dict)

  @classmethod
  def ToSymbol(cls, v):
    assert cls.IsEnum()
    for prop, value in vars(cls).iteritems():
      if value == v:
        return prop
    return v

  @classmethod
  def FromSymbol(cls, s):
    assert cls.IsEnum()
    return vars(cls)[s]

  @classmethod
  def Make(cls, **kwargs):
    return Message.Coerce(kwargs, cls)

  @classmethod
  def FromShallowDict(cls, d):
    return Message.Coerce(d, cls)

  @classmethod
  def FromJsonString(cls, s):
    d = json.loads(s, 'utf8')
    return cls.FromShallowDict(d)

  DESCRIPTOR = None


def message(cls):

  def Constructor(self, **kwargs):
    if len(kwargs) == 0:
      return
    self.__dict__ = cls.Make(**kwargs).__dict__

  setattr(cls, '__init__', Constructor)
  return cls


class AnnotationTypeValue(Message):
  BLAME = 0x00040
  CODE_FINDINGS = 0x40000
  COMPILER = 0x00080
  COVERAGE = 0x00010
  DEPRECATED = 0x02000
  FINDBUGS = 0x00200
  LANG_COUNT = 0x04000
  LINK_TO_DEFINITION = 0x00001
  LINK_TO_URL = 0x00002
  LINT = 0x00020
  OFFLINE_QUERIES = 0x08000
  OVERRIDE = 0x01000
  TOOLS = 0x20000
  UNKNOWN = 0x00000
  XREF_SIGNATURE = 0x00004

  DESCRIPTOR = int


@message
class AnnotationType(Message):
  DESCRIPTOR = {
      'id': AnnotationTypeValue,
  }


class TextRange(Message):
  DESCRIPTOR = {
      'start_line': int,
      'start_column': int,
      'end_line': int,
      'end_column': int,
  }

  def Contains(self, line, column):
    return not (line < self.start_line or line > self.end_line or
                (line == self.start_line and column < self.start_column) or
                (line == self.end_line and column > self.end_column))


class InternalLink(Message):
  DESCRIPTOR = {
      'package_name': str,
      'signature': str,
      'signature_hash': str,
      'path': str,
      'range': TextRange,
  }


class XrefSignature(Message):
  DESCRIPTOR = {
      'signature': str,
      'signature_hash': str,
  }


class NodeEnumKind(Message):
  ALIAS_JOIN = 9100
  ANNOTATION = 900
  ARRAY = 5700
  BIGFLOAT = 3000
  BIGINT = 2900
  BOOLEAN = 2000
  CHANNEL = 6700
  CHAR = 2100
  CLASS = 500
  COMMENT = 9400
  COMMUNICATION = 3850
  COMPLEX = 2800
  CONSTRUCTOR = 1200
  CONST_TYPE = 5400
  DEF_DECL_JOIN = 9000
  DELIMITER = 10000
  DIAGNOSTIC = 4100
  DIRECTORY = 4000
  DOCUMENTATION = 9800
  DOCUMENTATION_TAG = 9900
  DYNAMIC_TYPE = 9300
  ENUM = 700
  ENUM_CONSTANT = 800
  FIELD = 1500
  FILE = 3900
  FIXED_POINT = 2600
  FLOAT = 2500
  FORWARD_DECLARATION = 5300
  FUNCTION = 1000
  FUNCTION_TYPE = 10200
  IMPORT = 8200
  INDEX_INFO = 31337
  INSTANCE = 4600
  INTEGER = 2400
  INTERFACE = 600
  LABEL = 11600
  LIST = 6300
  LOCAL = 1600
  LOST = 9600
  MAP = 6000
  MARKUP_ATTRIBUTE = 11300
  MARKUP_TAG = 11200
  MATRIX = 5800
  METHOD = 1100
  MODULE = 300
  NAME = 3300
  NAMESPACE = 100
  NULL_TYPE = 7300
  NUMBER = 3100
  OBJECT = 4500
  OPAQUE = 6500
  OPTION_TYPE = 5500
  PACKAGE = 200
  PACKAGE_JOIN = 9200
  PARAMETER = 1700
  PARAMETRIC_TYPE = 5600
  POINTER = 5000
  PROPERTY = 1900
  QUEUE = 6400
  RATIONAL = 2700
  REFERENCE_TYPE = 5100
  REGEXP = 2300
  RESTRICTION_TYPE = 10100
  RULE = 8100
  SEARCHABLE_IDENTIFIER = 11500
  SEARCHABLE_NAME = 9500
  SET = 5900
  STRING = 2200
  STRUCT = 400
  SYMBOL = 3200
  TAG_NAME = 11100
  TARGET = 8000
  TEMPLATE = 1400
  TEXT = 9700
  TEXT_MACRO = 1300
  THREAD = 6600
  TUPLE = 6100
  TYPE_ALIAS = 5200
  TYPE_DESCRIPTOR = 11400
  TYPE_SPECIALIZATION = 7000
  TYPE_VARIABLE = 7100
  TYPE_VARIABLE_TYPE = 10400
  UNION = 6200
  UNIT_TYPE = 6900
  UNRESOLVED_TYPE = 404
  USAGE = 3800
  USER_TYPE = 10300
  VALUE = 3400
  VARIABLE = 1800
  VARIADIC_TYPE = 7200
  VOID_TYPE = 6800

  DESCRIPTOR = int


class KytheNodeEnumKind(Message):
  ABS = 100
  ABSVAR = 200
  ANCHOR = 300
  CONSTANT = 500
  DEPRECATED_CALLABLE = 400
  DOC = 550
  FILE = 600
  FUNCTION = 800
  FUNCTION_CONSTRUCTOR = 810
  FUNCTION_DESTRUCTOR = 820
  INTERFACE = 700
  LOOKUP = 900
  MACRO = 1000
  META = 1050
  NAME = 1100
  PACKAGE = 1200
  RECORD = 1300
  RECORD_CLASS = 1310
  RECORD_STRUCT = 1320
  RECORD_UNION = 1330
  SUM = 1400
  SUM_ENUM = 1410
  SUM_ENUM_CLASS = 1420
  TALIAS = 1500
  TAPP = 1600
  TBUILTIN = 1700
  TBUILTIN_ARRAY = 1705
  TBUILTIN_BOOLEAN = 1710
  TBUILTIN_BYTE = 1715
  TBUILTIN_CHAR = 1720
  TBUILTIN_DOUBLE = 1725
  TBUILTIN_FLOAT = 1730
  TBUILTIN_FN = 1735
  TBUILTIN_INT = 1740
  TBUILTIN_LONG = 1745
  TBUILTIN_PTR = 1750
  TBUILTIN_SHORT = 1755
  TBUILTIN_VOID = 1760
  TNOMINAL = 1800
  TSIGMA = 1850
  UNRESOLVED_TYPE = 0
  VARIABLE = 1900
  VARIABLE_FIELD = 1910
  VARIABLE_LOCAL = 1920
  VARIABLE_LOCAL_EXCEPTION = 1940
  VARIABLE_LOCAL_PARAMETER = 1930
  VARIABLE_LOCAL_RESOURCE = 1950
  VCS = 2000

  DESCRIPTOR = int


class Annotation(Message):
  DESCRIPTOR = {
      'content': str,
      'file_name': str,
      'internal_link': InternalLink,
      'is_implicit_target': bool,
      'kythe_xref_kind': KytheNodeEnumKind,
      'range': TextRange,
      'status': int,
      'type': AnnotationType,
      'url': str,
      'xref_kind': NodeEnumKind,
      'xref_signature': XrefSignature,
  }


@message
class FileSpec(Message):
  DESCRIPTOR = {'name': str, 'package_name': str}


class FormatType(Message):
  CARRIAGE_RETURN = 22
  CL_LINK = 33
  CODESEARCH_LINK = 36
  EXTERNAL_LINK = 31
  GOOGLE_INTERNAL_LINK = 30
  INCLUDE_QUERY = 35
  LINE = 1
  QUERY_MATCH = 40
  SNIPPET_QUERY_MATCH = 41
  SYNTAX_CLASS = 8
  SYNTAX_COMMENT = 5
  SYNTAX_CONST = 9
  SYNTAX_DEPRECATED = 11
  SYNTAX_DOC_NAME = 13
  SYNTAX_DOC_TAG = 12
  SYNTAX_ESCAPE_SEQUENCE = 10
  SYNTAX_KEYWORD = 3
  SYNTAX_KEYWORD_STRONG = 15
  SYNTAX_MACRO = 7
  SYNTAX_MARKUP_BOLD = 51
  SYNTAX_MARKUP_CODE = 54
  SYNTAX_MARKUP_ENTITY = 50
  SYNTAX_MARKUP_ITALIC = 52
  SYNTAX_MARKUP_LINK = 53
  SYNTAX_NUMBER = 6
  SYNTAX_PLAIN = 2
  SYNTAX_STRING = 4
  SYNTAX_TASK_TAG = 14
  TABS = 21
  TRAILING_SPACE = 20
  UNKNOWN_TYPE = 0
  USER_NAME_LINK = 32

  DESCRIPTOR = int


class FormatRange(Message):
  DESCRIPTOR = {'type': FormatType, 'range': TextRange, 'target': str}


class FileType(Message):
  BINARY = 5
  CODE = 1
  DATA = 3
  DIR = 4
  DOC = 2
  SYMLINK = 6
  UNKNOWN = 0

  DESCRIPTOR = int


class AnnotatedText(Message):
  DESCRIPTOR = {'text': str, 'range': [FormatRange]}


class CodeBlockType(Message):
  DESCRIPTOR = int

  ALLOCATION = 49
  ANONYMOUS_FUNCTION = 15
  BUILD_ARGUMENT = 25
  BUILD_BINARY = 21
  BUILD_GENERATOR = 24
  BUILD_LIBRARY = 23
  BUILD_RULE = 20
  BUILD_TEST = 22
  BUILD_VARIABLE = 26
  CLASS = 1
  COMMENT = 13
  DEFINE_CONST = 40
  DEFINE_MACRO = 41
  ENUM = 4
  ENUM_CONSTANT = 14
  ERROR = 0
  FIELD = 7
  FUNCTION = 8
  INTERFACE = 2
  JOB = 47
  JS_ASSIGNMENT = 38
  JS_CONST = 31
  JS_FUNCTION_ASSIGNMENT = 39
  JS_FUNCTION_LITERAL = 37
  JS_GETTER = 35
  JS_GOOG_PROVIDE = 32
  JS_GOOG_REQUIRE = 33
  JS_LITERAL = 36
  JS_SETTER = 34
  JS_VAR = 30
  METHOD = 6
  NAMESPACE = 11
  PACKAGE = 17
  PROPERTY = 12
  RESERVED_27 = 27
  RESERVED_28 = 28
  RESERVED_29 = 29
  SERVICE = 48
  STRUCT = 3
  TEMPLATE = 46
  TEST = 16
  TYPEDEF = 10
  UNION = 5
  VARIABLE = 9
  XML_TAG = 45


class Modifiers(Message):
  DESCRIPTOR = {
      '_global': bool,
      '_thread_local': bool,
      'abstract': bool,
      'anonymous': bool,
      'autogenerated': bool,
      'close_delimiter': bool,
      'constexpr_': bool,
      'declaration': bool,
      'definition': bool,
      'deprecated': bool,
      'discrete': bool,
      'dynamically_scoped': bool,
      'exported': bool,
      'file_scoped': bool,
      'foreign': bool,
      'getter': bool,
      'has_figment': bool,
      'immutable': bool,
      'implicit': bool,
      'inferred': bool,
      'is_figment': bool,
      'join_node': bool,
      'library_scoped': bool,
      'namespace_scoped': bool,
      'nonescaped': bool,
      'open_delimiter': bool,
      'operator': bool,
      'optional': bool,
      'package_scoped': bool,
      'parametric': bool,
      'predeclared': bool,
      'private': bool,
      'protected': bool,
      'public': bool,
      'receiver': bool,
      'register': bool,
      'renamed': bool,
      'repeated': bool,
      'setter': bool,
      'shadowing': bool,
      'signed': bool,
      'static': bool,
      'strict_math': bool,
      'synchronized': bool,
      'terminal': bool,
      'transient': bool,
      'unsigned': bool,
      'virtual': bool,
      'volatile': bool,
      'whitelisted': bool,
  }


class CodeBlock(Message):
  DESCRIPTOR = {
      'child': [Message.PARENT_TYPE],
      'modifiers': Modifiers,
      'name': str,
      'name_prefix': str,
      'signature': str,
      'text_range': TextRange,
      'type': CodeBlockType,
  }


class FileInfo(Message):
  DESCRIPTOR = {
      'actual_name': str,
      'changelist_num': str,
      'codeblock': [CodeBlock],
      'content': AnnotatedText,
      'converted_content': AnnotatedText,
      'converted_lines': int,
      'fold_ranges': [TextRange],
      'generated': bool,
      'generated_from': [str],
      'html_text': str,
      'language': str,
      'license_path': str,
      'license_type': str,
      'lines': int,
      'md5': str,
      'mime_type': str,
      'name': str,
      'package_name': str,
      'revision_num': str,
      'size': int,
      'type': FileType,
  }


class FileInfoResponse(Message):
  DESCRIPTOR = {
      'announcement': str,
      'error_message': str,
      'file_info': FileInfo,
      'return_code': int,
  }


@message
class FileInfoRequest(Message):
  DESCRIPTOR = {
      'file_spec': FileSpec,
      'fetch_html_content': bool,
      'fetch_outline': bool,
      'fetch_folding': bool,
      'fetch_generated_from': bool,
  }


class AnnotationResponse(Message):
  DESCRIPTOR = {
      'annotation': [Annotation],
      'file': str,
      'max_findings_reached': bool,
      'return_code': int,
  }


@message
class AnnotationRequest(Message):
  DESCRIPTOR = {
      'file_spec': FileSpec,
      'type': [AnnotationType],
  }


class MatchReason(Message):
  DESCRIPTOR = {
      'blame': bool,
      'content': bool,
      'filename': bool,
      'filename_lineno': bool,
      'scoped_symbol': bool,
  }


class Snippet(Message):
  DESCRIPTOR = {
      'first_line_number': int,
      'match_reason': MatchReason,
      'scope': str,
      'text': AnnotatedText,
  }


class Node(Message):
  DESCRIPTOR = {
      'call_scope_range': TextRange,
      'call_site_range': TextRange,
      'children': [Message.PARENT_TYPE],
      'display_name': str,
      'edge_kind': str,
      'file_path': str,
      'identifier': str,
      'node_kind': str,
      'override': bool,
      'package_name': str,
      'params': [str],
      'signature': str,
      'snippet': Snippet,
      'snippet_file_path': str,
      'snippet_package_name': str,
  }


class CallGraphResponse(Message):
  DESCRIPTOR = {
      'debug_message': str,
      'estimated_total_number_results': int,
      'is_call_graph': bool,
      'is_from_kythe': bool,
      'kythe_next_page_token': str,
      'node': Node,
      'results_offset': int,
      'return_code': int,
  }


@message
class CallGraphRequest(Message):
  DESCRIPTOR = {
      'file_spec': FileSpec,
      'max_num_results': int,
      'signature': str,
  }


class EdgeEnumKind(Message):
  DESCRIPTOR = int

  ALLOWED_ACCESS_TO = 4500
  ANNOTATED_WITH = 5000
  ANNOTATION_OF = 5100
  BASE_TYPE = 1300
  BELONGS_TO_NAMESPACE = 7200
  BELONGS_TO_PACKAGE = 6900
  CALL = 2200
  CALLED_AT = 2300
  CALLGRAPH_FROM = 4700
  CALLGRAPH_TO = 4600
  CAPTURED_BY = 1200
  CAPTURES = 1100
  CATCHES = 6400
  CAUGHT_BY = 6500
  CHANNEL_USED_BY = 2351
  CHILD = 5300
  COMMENT_IN_FILE = 7400
  COMPOSING_TYPE = 1400
  CONSUMED_BY = 4100
  CONTAINS_COMMENT = 7500
  CONTAINS_DECLARATION = 5800
  CONTAINS_USAGE = 6000
  DECLARATION_IN_FILE = 5900
  DECLARATION_OF = 3200
  DECLARED_BY = 400
  DECLARES = 300
  DEFINITION_OF = 3400
  DIAGNOSTIC_OF = 5400
  DIRECTLY_INHERITED_BY = 1060
  DIRECTLY_INHERITS = 1050
  DIRECTLY_OVERRIDDEN_BY = 860
  DIRECTLY_OVERRIDES = 850
  DOCUMENTED_WITH = 7700
  DOCUMENTS = 7600
  ENCLOSED_USAGE = 4900
  EXTENDED_BY = 200
  EXTENDS = 100
  GENERATED_BY = 3100
  GENERATES = 3000
  GENERATES_NAME = 3150
  HAS_DECLARATION = 3300
  HAS_DEFINITION = 3500
  HAS_DIAGNOSTIC = 5500
  HAS_FIGMENT = 9200
  HAS_IDENTIFIER = 9400
  HAS_INPUT = 4000
  HAS_OUTPUT = 4200
  HAS_PROPERTY = 2800
  HAS_SELECTION = 10900
  HAS_TYPE = 1800
  IMPLEMENTED_BY = 600
  IMPLEMENTS = 500
  INHERITED_BY = 1000
  INHERITS = 900
  INITIALIZED_WITH = 9100
  INITIALIZES = 9000
  INJECTED_AT = 10500
  INJECTS = 10400
  INSTANTIATED_AT = 2500
  INSTANTIATION = 2400
  IS_FIGMENT_OF = 9300
  IS_IDENTIFIER_OF = 9500
  IS_TYPE_OF = 1900
  KEY_METHOD = 3600
  KEY_METHOD_OF = 3700
  MEMBER_SELECTED_AT = 10700
  NAMESPACE_CONTAINS = 7300
  NAME_GENERATED_BY = 3160
  OUTLINE_CHILD = 5700
  OUTLINE_PARENT = 5600
  OVERRIDDEN_BY = 800
  OVERRIDES = 700
  PACKAGE_CONTAINS = 6800
  PARAMETER_TYPE = 8800
  PARAMETER_TYPE_OF = 8900
  PARENT = 5200
  PRODUCED_BY = 4300
  PROPERTY_OF = 2900
  RECEIVES_FROM = 2353
  REFERENCE = 2600
  REFERENCED_AT = 2700
  REQUIRED_BY = 3900
  REQUIRES = 3800
  RESTRICTED_TO = 4400
  RETURNED_BY = 2100
  RETURN_TYPE = 2000
  SELECTED_FROM = 10800
  SELECTS_MEMBER_OF = 10600
  SENDS_TO = 2352
  SPECIALIZATION_OF = 1600
  SPECIALIZED_BY = 1700
  THROWGRAPH_FROM = 6700
  THROWGRAPH_TO = 6600
  THROWN_BY = 6300
  THROWS = 6200
  TREE_CHILD = 7900
  TREE_PARENT = 7800
  TYPE_PARAMETER = 1500
  TYPE_PARAMETER_OF = 1550
  USAGE_CONTEXT = 4800
  USAGE_IN_FILE = 6100
  USES_CHANNEL = 2350
  USES_VARIABLE = 7000
  VARIABLE_USED_IN = 7100
  XLANG_PROVIDES = 8600
  XLANG_PROVIDES_NAME = 8400
  XLANG_USES = 8700
  XLANG_USES_NAME = 8500


class XrefTypeCount(Message):
  DESCRIPTOR = {
      'count': int,
      'type': str,
      'type_id': int,
  }


class XrefSingleMatch(Message):
  DESCRIPTOR = {
      'line_number': int,
      'line_text': str,
      'type': str,
      'type_id': EdgeEnumKind,
      'grok_modifiers': Modifiers,
      'signature': str,
  }


class XrefSearchResult(Message):
  DESCRIPTOR = {
      'file': FileSpec,
      'match': [XrefSingleMatch],
  }


class XrefSearchResponse(Message):
  DESCRIPTOR = {
      'eliminated_type_count': [XrefTypeCount],
      'estimated_total_type_count': [XrefTypeCount],
      'from_kythe': bool,
      'grok_total_number_of_results': int,
      'search_result': [XrefSearchResult],
      'status': int,
      'status_message': str,
  }


@message
class XrefSearchRequest(Message):
  DESCRIPTOR = {
      'edge_filter': [EdgeEnumKind],
      'file_spec': FileSpec,
      'max_num_results': int,
      'query': str,
  }


class VanityGitOnBorgHostname(Message):
  DESCRIPTOR = {
      'name': str,
      'hostname': str,
  }


class InternalPackage(Message):
  DESCRIPTOR = {
      'browse_path_prefix': str,
      'cs_changelist_num': str,
      'grok_languages': [str],
      'grok_name': str,
      'grok_path_prefix': [str],
      'id': str,
      'kythe_languages': [str],
      'name': str,
      'repo': str,
      'vanity_git_on_borg_hostnames': [VanityGitOnBorgHostname],
  }


class StatusResponse(Message):
  DESCRIPTOR = {
      'announcement': str,
      'build_label': str,
      'internal_package': [InternalPackage],
      'success': bool,
  }


class GobInfo(Message):
  DESCRIPTOR = {
      'commit': str,
      'path': str,
      'repo': str,
  }


class DirInfoResponseChild(Message):
  DESCRIPTOR = {
      'is_deleted': bool,
      'is_directory': bool,
      'name': str,
      'package_id': str,
      'path': str,
      'revision_num': str,
  }


class DirInfoResponseParent(Message):
  DESCRIPTOR = {
      'name': str,
      'path': str,
      'package_id': str,
  }


class DirInfoResponse(Message):
  DESCRIPTOR = {
      'child': [DirInfoResponseChild],
      'generated': bool,
      'gob_info': GobInfo,
      'name': str,
      'package_id': str,
      'parent': [DirInfoResponseParent],
      'path': str,
      'success': bool,
  }


@message
class DirInfoRequest(Message):
  DESCRIPTOR = {
      'file_spec': FileSpec,
  }


class FileResult(Message):
  DESCRIPTOR = {
      'display_name': AnnotatedText,
      'file': FileSpec,
      'license': FileSpec,
      'license_type': str,
      'size': int,
  }


class SingleMatch(Message):
  DESCRIPTOR = {
      'line_number': int,
      'line_text': str,
      'match_length': int,
      'match_offset': int,
      'post_context_num_lines': int,
      'post_context_text': str,
      'pre_context_num_lines': int,
      'pre_context_text': str,
      'score': int,
  }


class SearchResult(Message):
  DESCRIPTOR = {
      'best_matching_line_number': int,
      'children': [str],
      'docid': str,
      'duplicate': [FileResult],
      'has_unshown_matches': bool,
      'hit_max_matches': bool,
      'is_augmented': bool,
      'language': str,
      'match': [SingleMatch],
      'match_reason': MatchReason,
      'num_duplicates': int,
      'num_matches': int,
      'snippet': [Snippet],
      'top_file': FileResult,
  }


class SearchResponse(Message):
  DESCRIPTOR = {
      'estimated_total_number_of_results': int,
      'hit_max_matches_per_file': bool,
      'hit_max_results': bool,
      'hit_max_to_score': bool,
      'maybe_skipped_documents': bool,
      'results_offset': int,
      'search_result': [SearchResult],
      'status': int,
      'status_message': str,
  }


@message
class SearchRequest(Message):
  DESCRIPTOR = {
      'exhaustive': bool,
      'lines_context': int,
      'max_num_results': int,
      'query': str,
      'return_all_duplicates': bool,
      'return_all_snippets': bool,
      'return_decorated_snippets': bool,
      'return_directories': bool,
      'return_line_matches': bool,
      'return_snippets': bool,
  }


class StatusRequest(Message):
  DESCRIPTOR = {}


class CompoundResponse(Message):
  DESCRIPTOR = {
      'annotation_response': [AnnotationResponse],
      'call_graph_response': [CallGraphResponse],
      'dir_info_response': [DirInfoResponse],
      'file_info_response': [FileInfoResponse],
      'search_response': [SearchResponse],
      'status_response': [StatusResponse],
      'xref_search_response': [XrefSearchResponse],
  }


@message
class CompoundRequest(Message):
  DESCRIPTOR = {
      'annotation_request': [AnnotationRequest],
      'call_graph_request': [CallGraphRequest],
      'dir_info_request': [DirInfoRequest],
      'file_info_request': [FileInfoRequest],
      'search_request': [SearchRequest],
      'status_request': [StatusRequest],
      'xref_search_request': [XrefSearchRequest],
  }

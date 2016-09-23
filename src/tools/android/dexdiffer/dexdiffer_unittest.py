#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Tests for dexdiffer."""

import dexdiffer
import json
import unittest


class DexdifferTest(unittest.TestCase):

  def testReadDict(self):
    mapping_file = [
        'package.ClassName -> package.qq:\n',
        'android.support.v8.MenuPopupHelper -> android.support.v8.v:',
        '    android.view.LayoutInflater mInflater -> d\n',
        '    117:118:void setForceShowIcon(boolean) -> b',
        '    1:1:package.ClassName <init>(int,int) -> <init>',
    ]
    expected = {
        'package.qq': ['package.ClassName', {}],
        'android.support.v8.v':
        ['android.support.v8.MenuPopupHelper',
         {'android.view.LayoutInflater d':
              'android.view.LayoutInflater mInflater',
          'void b(boolean)': 'void setForceShowIcon(boolean)',
          'package.ClassName <init>(int,int)':
              'package.ClassName <init>(int,int)'}],
    }

    actual = dexdiffer._ReadMappingDict(mapping_file)
    self.assertDeepEqual(actual, expected)

  def testGetLineTokens1(self):
    line = '        public  void <init> (android.content.Context,float); // Cxr'
    expected = ['void', '<init>', 'android.content.Context', 'float']
    actual = dexdiffer._GetLineTokens(line)
    self.assertDeepEqual(actual, expected)

  def testGetLineTokens2(self):
    line = '/** asdfasdf /**/ private final static   /*asdf*/int varname$1;'
    expected = ['int', 'varname$1']
    actual = dexdiffer._GetLineTokens(line)
    self.assertDeepEqual(actual, expected)

  def testGetLineTokens3(self):
    line = 'int[] varname_1;'
    expected = ['int[]', 'varname_1']
    actual = dexdiffer._GetLineTokens(line)
    self.assertDeepEqual(actual, expected)

  def testGetLineTokensEmpty(self):
    line = '/***/   /*asdf*/ //comment;'
    expected = []
    actual = dexdiffer._GetLineTokens(line)
    self.assertDeepEqual(actual, expected)

  def testGetMemberIdentifier(self):
    line_tokens = ['void', 'b', 'boolean', 'rnmd[]']
    expected = 'void foo(boolean,renamed.type[])'
    renamed_class_name = 'renamed.class'
    mapping_dict = { renamed_class_name : [ 'actual.class.name', {
        'void b': 'void variable_name',
        'boolean a': 'boolean variable_name2',
        'void b(boolean,renamed.type)':
            'void wrong_function(boolean,renamed.type)',
        'void b(boolean,renamed.type[])': expected,
    }], 'rnmd': ['renamed.type', {}]}
    actual = dexdiffer._GetMemberIdentifier(line_tokens, mapping_dict,
                                             renamed_class_name, True)
    self.assertEqual(expected, actual)

  def testIsLineFunctionDefinition(self):
    line = 'java.lang.String  CONSOLE_ELISION= "[(0)]"'
    self.assertFalse(dexdiffer._IsLineFunctionDefinition(line))

  def testStripQuotes(self):
    string = 'abc\'123\'"456"def\'"7"\''
    self.assertEqual('abcdef', dexdiffer._StripQuotes(string))

  def testBuildMappedDexDict(self):
    dextra_output = [
'/* 3396 */ public class   org.chromium.chrome.browser.widget.a',
'           extends android.view.View    {',
'         /** 2 Instance Fields  **/',
'          private  org.chromium.chrome.browser.widget.b$1      x;',
'          private  int  mPosition;',
'         /** 1 Direct Methods  **/',
'         public  void <init> (android.content.Context, android.util.Attribute'
              'Set); // Constructor',
'         /** 2 Virtual Methods  **/',
'         public  void init (int, int);',
'         protected  void onDraw (android.graphics.Canvas);',
'        }  // end class org.chromium.chrome.browser.widget.a',
'/* 3397 */ class   org.chromium.chrome.browser.widget.b$1',
'           implements android.text.TextWatcher  {',
'         /** 1 Instance Fields  **/',
'          final  org.chromium.chrome.browser.widget.FloatLabelLayout'
              '    this$0;',
'         /** 1 Direct Methods  **/',
'          bool <init> (); // Constructor',
'         /** 1 Virtual Methods  **/',
'         public  void x (org.chromium.chrome.browser.widget.a, int, int,'
              ' int);',
'        }  // end class org.chromium.chrome.browser.widget.b$1']
    mapping_dict = {
        'org.chromium.chrome.browser.widget.a': ['class_name_a', {
            'class_name_b$1 x': 'class_name_b$1 full_member_variable',
            'int mPosition': 'int mPosition',
            'void <init>(android.content.Context,android.util.AttributeSet)':
              'void <init>(android.content.Context,android.util.AttributeSet)',
            'void init(int,int)': 'void init(int,int)',
            'void onDraw(android.graphics.Canvas)':
                'void onDraw(android.graphics.Canvas)',
        }],
        'org.chromium.chrome.browser.widget.b$1': ['class_name_b$1', {
            'org.chromium.chrome.browser.widget.FloatLabelLayout this$0':
              'org.chromium.chrome.browser.widget.FloatLabelLayout this$0',
            'boolean <init>()': 'boolean <init>()',
            'void x(class_name_a,int,int,int)':
              'void full_function_name(class_name_a,int,int,int)'
          }],
    }
    actual = dexdiffer._BuildMappedDexDict(dextra_output, mapping_dict)
    expected = { 'class_name_a': [
        'class_name_b$1 full_member_variable',
        'int mPosition',
        'void <init>(android.content.Context,android.util.AttributeSet)',
        'void init(int,int)',
        'void onDraw(android.graphics.Canvas)'
    ], 'class_name_b$1': [
        'org.chromium.chrome.browser.widget.FloatLabelLayout this$0',
        'boolean <init>()',
        'void full_function_name(class_name_a,int,int,int)'
    ]}
    self.assertDeepEqual(actual, expected)

  def testParseMappingLine(self):
    orig_name = "abc.q12$1"
    new_name = "a$1"
    line = orig_name + " -> " + new_name
    actual_orig_name, actual_new_name = dexdiffer._ParseMappingLine(line)
    self.assertEqual(orig_name, actual_orig_name)
    self.assertEqual(new_name, actual_new_name)

  def testDiffDexDicts(self):
    base_dict = { 'class_name_a': [
        'class_name_b$1 full_member_variable',
        'int mPosition',
        'void <init>(android.content.Context,android.util.AttributeSet)',
        'void init(int,int)',
        'void onDraw(android.graphics.Canvas)'
    ], 'class_name_b$1': [
        'org.chromium.chrome.browser.widget.FloatLabelLayout this$0',
        'void <init>()',
        'void full_function_name(class_name_a,int,int)'
    ], 'class_name_deleted': []}
    new_dict = { 'class_name_a': [
        'class_name_b$1 full_member_variable',
        'int mPosition',
        'void <init>(android.content.Context,android.util.AttributeSet)',
        'void init(int,int)',
        'void onDraw(android.graphics.Canvas)'
    ], 'class_name_b$1': [
        'org.chromium.chrome.browser.widget.FloatLabelLayout this$0',
        'void <init>()',
        'void full_function_name(int,int,int)'
    ], 'class_name_new': []}
    actual = dexdiffer._DiffDexDicts(base_dict, new_dict)
    expected = [('class_name_b$1\n'
                 '-  void full_function_name(class_name_a,int,int)\n'
                 '+  void full_function_name(int,int,int)'),
                '-class class_name_deleted',
                '+class class_name_new']

    self.assertDeepEqual(actual, expected)

  def assertDeepEqual(self, actual, expected):
    # Only designed to work for json-able types
    a = json.dumps(actual, sort_keys=True)
    e = json.dumps(expected, sort_keys=True)
    self.assertEqual(a, e)

if __name__ == '__main__':
  unittest.main()

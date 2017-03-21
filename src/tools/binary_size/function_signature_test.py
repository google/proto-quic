#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import sys
import unittest

import function_signature


class AnalyzeTest(unittest.TestCase):

  def testParseFunctionSignature(self):
    def check(ret_part, name_part, params_part, after_part=''):
      signature = ''.join((name_part, params_part, after_part))
      got_full, got_name = function_signature.Parse(signature)
      self.assertEqual(name_part + after_part, got_name)
      self.assertEqual(name_part + params_part + after_part, got_full)
      if ret_part:
        signature = ''.join((ret_part, name_part, params_part, after_part))
        got_full, got_name = function_signature.Parse(signature)
        self.assertEqual(name_part + after_part, got_name)
        self.assertEqual(name_part + params_part + after_part, got_full)

    check('bool ',
          'foo::Bar<unsigned int, int>::Do<unsigned int>',
          '(unsigned int)')
    check('base::internal::CheckedNumeric<int>& ',
          'base::internal::CheckedNumeric<int>::operator+=<int>',
          '(int)')
    check('base::internal::CheckedNumeric<int>& ',
          'b::i::CheckedNumeric<int>::MathOp<b::i::CheckedAddOp, int>',
          '(int)')
    check('', '(anonymous namespace)::GetBridge', '(long long)')
    check('', 'operator delete', '(void*)')
    check('', 'b::i::DstRangeRelationToSrcRangeImpl<long long, long long, '
              'std::__ndk1::numeric_limits, (b::i::Integer)1>::Check',
          '(long long)')
    check('', 'cc::LayerIterator::operator cc::LayerIteratorPosition const',
          '()',
          ' const')
    check('decltype ({parm#1}((SkRecords::NoOp)())) ',
          'SkRecord::Record::visit<SkRecords::Draw&>',
          '(SkRecords::Draw&)',
          ' const')
    check('', 'base::internal::BindStateBase::BindStateBase',
          '(void (*)(), void (*)(base::internal::BindStateBase const*))')
    check('int ', 'std::__ndk1::__c11_atomic_load<int>',
          '(std::__ndk1::<int> volatile*, std::__ndk1::memory_order)')
    check('std::basic_ostream<char, std::char_traits<char> >& ',
          'std::operator<< <std::char_traits<char> >',
          '(std::basic_ostream<char, std::char_traits<char> >&, char)')
    check('v8::internal::SlotCallbackResult ',
          'v8::internal::UpdateTypedSlotHelper::UpdateCodeTarget'
          '<v8::PointerUpdateJobTraits<(v8::Direction)1>::Foo(v8::Heap*, '
          'v8::MemoryChunk*)::{lambda(v8::SlotType, unsigned char*)#2}::'
          'operator()(v8::SlotType, unsigned char*, unsigned char*) '
          'const::{lambda(v8::Object**)#1}>',
          '(v8::RelocInfo, v8::Foo<(v8::PointerDirection)1>::Bar(v8::Heap*)::'
          '{lambda(v8::SlotType)#2}::operator()(v8::SlotType) const::'
          '{lambda(v8::Object**)#1})')
    check('',
          'WTF::StringAppend<WTF::String, WTF::String>::operator WTF::String',
          '()',
          ' const')
    # Make sure []s are not removed from the name part.
    check('', 'Foo', '()', ' [virtual thunk]')

    # SkArithmeticImageFilter.cpp has class within function body. e.g.:
    #   ArithmeticFP::onCreateGLSLInstance() looks like:
    # class ArithmeticFP {
    #   GrGLSLFragmentProcessor* onCreateGLSLInstance() const {
    #     class GLSLFP {
    #       void emitCode(EmitArgs& args) { ... }
    #     };
    #     ...
    #   }
    # };
    SIG = '(anonymous namespace)::Foo::Baz() const::GLSLFP::onData(Foo, Bar)'
    got_full, got_name = function_signature.Parse(SIG)
    self.assertEqual('(anonymous namespace)::Foo::Baz', got_name)
    self.assertEqual(SIG, got_full)


if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG,
                      format='%(levelname).1s %(relativeCreated)6d %(message)s')
  unittest.main()

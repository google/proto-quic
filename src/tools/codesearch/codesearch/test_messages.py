# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from __future__ import absolute_import

import unittest

from .messages import Message, message


@message
class Foo(Message):
  DESCRIPTOR = {'x': int}


class Bar(Message):
  DESCRIPTOR = {'x': int, 'y': Message.PARENT_TYPE}


class Baz(Message):
  DESCRIPTOR = {'x': int, 'y': [Message.PARENT_TYPE]}


class Qux(Message):
  FOO = 1
  BAR = 2

  DESCRIPTOR = int


class Quux(Message):
  DESCRIPTOR = {'x': Qux}


class TestProto(unittest.TestCase):

  def test_proto_bridge(self):
    v = Foo()
    v.x = 3
    self.assertEqual(v.AsQueryString(), [('x', '3')])

  def test_from_json_string_1(self):
    v = Message.FromJsonString('{"x": 3}')
    self.assertEqual(v.x, 3)

  def test_from_json_string_2(self):
    v = Foo.FromJsonString('{"x": 3}')
    self.assertTrue(isinstance(v, Foo))
    self.assertTrue(isinstance(v.x, int))
    self.assertEqual(v.x, 3)

  def test_from_json_string_3(self):
    v = Bar.FromJsonString('{"x": 3, "y": {"x": 4}}')
    self.assertTrue(isinstance(v, Bar))
    self.assertTrue(isinstance(v.y, Bar))
    self.assertEqual(v.x, 3)
    self.assertEqual(v.y.x, 4)

  def test_from_json_string_4(self):
    v = Foo.FromJsonString('{"y": 3}')
    self.assertTrue(isinstance(v, Foo))

  def test_from_json_string_5(self):
    v = Foo.FromJsonString('{"y": 3}')
    self.assertTrue(isinstance(v, Foo))
    self.assertEqual(v.y, 3)

  def test_from_json_string_6(self):
    v = Quux.FromJsonString('{"x": 3}')
    self.assertTrue(isinstance(v, Quux))
    self.assertTrue(isinstance(v.x, int))
    self.assertEqual(v.x, 3)

  def test_from_json_string_7(self):
    v = Quux.FromJsonString('{"x": "FOO"}')
    self.assertTrue(isinstance(v, Quux))
    self.assertTrue(isinstance(v.x, int))
    self.assertEqual(v.x, 1)

  def test_from_shallow_dict_1(self):
    v = Baz.FromShallowDict({'x': 3, 'y': [{'x': 4}, {'x': 5}]})
    self.assertTrue(isinstance(v, Baz))
    self.assertTrue(isinstance(v.y, list))
    self.assertTrue(isinstance(v.y[0], Baz))
    self.assertTrue(isinstance(v.y[1], Baz))


class TestConstructor(unittest.TestCase):

  def test_empty_class(self):
    f = Foo()
    self.assertFalse(hasattr(f, 'x'))

  def test_class_with_known_keyword(self):
    f = Foo(x=10)
    self.assertTrue(hasattr(f, 'x'))
    self.assertEqual(10, f.x)

  def test_class_with_unknown_keyword(self):
    f = Foo(x=10, y=9)
    self.assertTrue(hasattr(f, 'x'))
    self.assertTrue(hasattr(f, 'y'))
    self.assertEqual(9, f.y)


if __name__ == '__main__':
  unittest.main()

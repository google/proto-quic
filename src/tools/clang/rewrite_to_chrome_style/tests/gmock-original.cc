// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gmock/gmock.h"

namespace blink {

class Interface {
 public:
  virtual void myMethod(int my_param) {}
};

class MockedInterface : public Interface {
 public:
  MOCK_METHOD1(myMethod, void(int));
};

void test() {
  MockedInterface mockedInterface;
  EXPECT_CALL(mockedInterface, myMethod(1));
  EXPECT_CALL(
      mockedInterface,  // A comment to prevent reformatting into single line.
      myMethod(1));
  mockedInterface.myMethod(123);
}

}  // namespace blink

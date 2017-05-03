// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_API_QUIC_TEST_H_
#define NET_QUIC_PLATFORM_API_QUIC_TEST_H_

#include "net/quic/platform/impl/quic_test_impl.h"

// Defines the base classes to be used in QUIC tests.
using QuicTest = QuicTestImpl;
template <class T>
using QuicTestWithParam = QuicTestWithParamImpl<T>;

#endif  // NET_QUIC_PLATFORM_API_QUIC_TEST_H_

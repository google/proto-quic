// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/sequence_token.h"

#include "base/atomic_sequence_num.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/threading/thread_local.h"

namespace base {

namespace {

base::StaticAtomicSequenceNumber g_sequence_token_generator;

LazyInstance<ThreadLocalPointer<ScopedSetSequenceTokenForCurrentThread>>::Leaky
    tls_current_sequence_token = LAZY_INSTANCE_INITIALIZER;

}  // namespace

bool SequenceToken::operator==(const SequenceToken& other) const {
  return token_ == other.token_ && token_ != kInvalidSequenceToken;
}

bool SequenceToken::operator!=(const SequenceToken& other) const {
  return !(*this == other);
}

bool SequenceToken::IsValid() const {
  return token_ != kInvalidSequenceToken;
}

SequenceToken SequenceToken::Create() {
  return SequenceToken(g_sequence_token_generator.GetNext());
}

SequenceToken SequenceToken::GetForCurrentThread() {
  const ScopedSetSequenceTokenForCurrentThread* current_sequence_token =
      tls_current_sequence_token.Get().Get();
  return current_sequence_token ? current_sequence_token->token_
                                : SequenceToken();
}

ScopedSetSequenceTokenForCurrentThread::ScopedSetSequenceTokenForCurrentThread(
    const SequenceToken& token)
    : token_(token) {
  DCHECK(!tls_current_sequence_token.Get().Get());
  tls_current_sequence_token.Get().Set(this);
}

ScopedSetSequenceTokenForCurrentThread::
    ~ScopedSetSequenceTokenForCurrentThread() {
  DCHECK_EQ(tls_current_sequence_token.Get().Get(), this);
  tls_current_sequence_token.Get().Set(nullptr);
}

}  // namespace base

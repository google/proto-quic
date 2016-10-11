// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Multiply-included file, hence no include guard.
// Inclusion of all message files recognized by message_lib. All messages
// received by RenderProcessHost should be included here for the IPC fuzzer.

// Force all multi-include optional files to be included again.
#undef CHROME_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#undef COMPONENTS_AUTOFILL_CONTENT_COMMON_AUTOFILL_PARAM_TRAITS_MACROS_H_
#undef COMPONENTS_NACL_COMMON_NACL_TYPES_PARAM_TRAITS_H_
#undef CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_
#undef CONTENT_COMMON_FRAME_PARAM_MACROS_H_
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_

#include "chrome/common/all_messages.h"
#if !defined(DISABLE_NACL)
#include "components/nacl/common/nacl_host_messages.h"
#endif
#include "components/network_hints/common/network_hints_message_generator.h"
#include "components/pdf/common/pdf_message_generator.h"
#include "components/spellcheck/common/spellcheck_message_generator.h"
#include "components/tracing/common/tracing_messages.h"
#include "content/common/all_messages.h"
#include "extensions/common/extension_message_generator.h"

// Protocol Buffers - Google's data interchange format
// Copyright 2017 Google Inc.  All rights reserved.
// https://developers.google.com/protocol-buffers/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <google/protobuf/arena.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/stubs/atomicops.h>
#include <google/protobuf/stubs/hash.h>

namespace google {
namespace protobuf {

#if !defined(GOOGLE_PROTOBUF_NO_THREADLOCAL) && defined(PROTOBUF_USE_DLLS)
Arena::ThreadCache& Arena::cr_thread_cache() {
  static GOOGLE_THREAD_LOCAL ThreadCache cr_thread_cache_ = {-1, NULL};
  return cr_thread_cache_;
}
#endif

namespace internal {

SequenceNumber cr_lifecycle_id_generator_;

const ::std::string* cr_empty_string_;
GOOGLE_PROTOBUF_DECLARE_ONCE(cr_empty_string_once_init_);

const RepeatedField<int32>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_int32_ = NULL;
const RepeatedField<int64>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_int64_ = NULL;
const RepeatedField<uint32>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_uint32_ =
        NULL;
const RepeatedField<uint64>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_uint64_ =
        NULL;
const RepeatedField<double>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_double_ =
        NULL;
const RepeatedField<float>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_float_ = NULL;
const RepeatedField<bool>*
    RepeatedPrimitiveGenericTypeTraits::cr_default_repeated_field_bool_ = NULL;
const RepeatedStringTypeTraits::RepeatedFieldType*
    RepeatedStringTypeTraits::cr_default_repeated_field_ = NULL;
const RepeatedMessageGenericTypeTraits::RepeatedFieldType*
    RepeatedMessageGenericTypeTraits::cr_default_repeated_field_ = NULL;

LIBPROTOBUF_EXPORT vector<void (*)()>* cr_shutdown_functions = NULL;
LIBPROTOBUF_EXPORT Mutex* cr_shutdown_functions_mutex = NULL;
LIBPROTOBUF_EXPORT GOOGLE_PROTOBUF_DECLARE_ONCE(cr_shutdown_functions_init);

LIBPROTOBUF_EXPORT LogHandler* cr_log_handler_ = NULL;
LIBPROTOBUF_EXPORT int cr_log_silencer_count_ = 0;

LIBPROTOBUF_EXPORT Mutex* cr_log_silencer_count_mutex_ = NULL;
LIBPROTOBUF_EXPORT GOOGLE_PROTOBUF_DECLARE_ONCE(cr_log_silencer_count_init_);

GOOGLE_PROTOBUF_DECLARE_ONCE(
    cr_repeated_primitive_generic_type_traits_once_init_);
GOOGLE_PROTOBUF_DECLARE_ONCE(cr_repeated_string_type_traits_once_init_);
GOOGLE_PROTOBUF_DECLARE_ONCE(
    cr_repeated_message_generic_type_traits_once_init_);

LIBPROTOBUF_EXPORT hash_map<pair<const MessageLite*, int>, ExtensionInfo>*
    cr_registry_ = NULL;
LIBPROTOBUF_EXPORT GOOGLE_PROTOBUF_DECLARE_ONCE(cr_registry_init_);

LIBPROTOBUF_EXPORT bool cr_module_initialized_ = false;
struct InitDetector {
  InitDetector() { cr_module_initialized_ = true; }
};
InitDetector cr_init_detector;

#ifdef GOOGLE_PROTOBUF_ATOMICOPS_INTERNALS_X86_GCC_H_
// Set the flags so that code will run correctly and conservatively, so even
// if we haven't been initialized yet, we're probably single threaded, and our
// default values should hopefully be pretty safe.
LIBPROTOBUF_EXPORT struct AtomicOps_x86CPUFeatureStruct
    cr_AtomicOps_Internalx86CPUFeatures = {
        false,  // bug can't exist before process spawns multiple threads
        false,  // no SSE2
};

class AtomicOpsx86Initializer {
 public:
  AtomicOpsx86Initializer() { AtomicOps_Internalx86CPUFeaturesInit(); }
};

AtomicOpsx86Initializer cr_g_initer;
#endif

}  // namespace internal
}  // namespace protobuf
}  // namespace google

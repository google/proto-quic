// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
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

#ifndef __GOOGLE_PROTOBUF_PHP_PROTOBUF_H__
#define __GOOGLE_PROTOBUF_PHP_PROTOBUF_H__

#include <php.h>

// ubp.h has to be placed after php.h. Othwise, php.h will introduce NDEBUG.
#include "upb.h"

#define PHP_PROTOBUF_EXTNAME "protobuf"
#define PHP_PROTOBUF_VERSION "3.3.2"

#define MAX_LENGTH_OF_INT64 20
#define SIZEOF_INT64 8

// -----------------------------------------------------------------------------
// PHP7 Wrappers
// ----------------------------------------------------------------------------

#if PHP_MAJOR_VERSION < 7

#define php_proto_zend_literal const zend_literal*
#define PHP_PROTO_CASE_IS_BOOL IS_BOOL
#define PHP_PROTO_SIZE int
#define PHP_PROTO_LONG long
#define PHP_PROTO_TSRMLS_DC TSRMLS_DC
#define PHP_PROTO_TSRMLS_CC TSRMLS_CC

// PHP String

#define PHP_PROTO_ZVAL_STRING(zval_ptr, s, copy) \
  ZVAL_STRING(zval_ptr, s, copy)
#define PHP_PROTO_ZVAL_STRINGL(zval_ptr, s, len, copy) \
  ZVAL_STRINGL(zval_ptr, s, len, copy)
#define PHP_PROTO_RETURN_STRING(s, copy) RETURN_STRING(s, copy)
#define PHP_PROTO_RETURN_STRINGL(s, len, copy) RETURN_STRINGL(s, len, copy)
#define PHP_PROTO_RETVAL_STRINGL(s, len, copy) RETVAL_STRINGL(s, len, copy)
#define php_proto_zend_make_printable_zval(from, to) \
  {                                                  \
    int use_copy;                                    \
    zend_make_printable_zval(from, to, &use_copy);   \
  }

// PHP Array

#define PHP_PROTO_HASH_OF(array) Z_ARRVAL_P(array)

#define php_proto_zend_hash_index_update(ht, h, pData, nDataSize, pDest) \
  zend_hash_index_update(ht, h, pData, nDataSize, pDest)

#define php_proto_zend_hash_index_find(ht, h, pDest) \
  zend_hash_index_find(ht, h, pDest)

#define php_proto_zend_hash_next_index_insert(ht, pData, nDataSize, pDest) \
  zend_hash_next_index_insert(ht, pData, nDataSize, pDest)

#define php_proto_zend_hash_get_current_data_ex(ht, pDest, pos) \
  zend_hash_get_current_data_ex(ht, pDest, pos)

// PHP Object

#define PHP_PROTO_WRAP_OBJECT_START(name) \
  struct name {                           \
    zend_object std;
#define PHP_PROTO_WRAP_OBJECT_END \
  };

#define PHP_PROTO_INIT_CLASS_START(CLASSNAME, CAMELNAME, LOWWERNAME)         \
  void LOWWERNAME##_init(TSRMLS_D) {                                         \
    zend_class_entry class_type;                                             \
    const char* class_name = CLASSNAME;                                      \
    INIT_CLASS_ENTRY_EX(class_type, CLASSNAME, strlen(CLASSNAME),            \
                        LOWWERNAME##_methods);                               \
    LOWWERNAME##_type = zend_register_internal_class(&class_type TSRMLS_CC); \
    LOWWERNAME##_type->create_object = LOWWERNAME##_create;                  \
    LOWWERNAME##_handlers = PEMALLOC(zend_object_handlers);                  \
    memcpy(LOWWERNAME##_handlers, zend_get_std_object_handlers(),            \
           sizeof(zend_object_handlers));
#define PHP_PROTO_INIT_CLASS_END \
  }

#define PHP_PROTO_OBJECT_CREATE_START(NAME, LOWWERNAME) \
  static zend_object_value LOWWERNAME##_create(         \
      zend_class_entry* ce TSRMLS_DC) {                 \
    PHP_PROTO_ALLOC_CLASS_OBJECT(NAME, ce);             \
    zend_object_std_init(&intern->std, ce TSRMLS_CC);   \
    object_properties_init(&intern->std, ce);
#define PHP_PROTO_OBJECT_CREATE_END(NAME, LOWWERNAME)                          \
  PHP_PROTO_FREE_CLASS_OBJECT(NAME, LOWWERNAME##_free, LOWWERNAME##_handlers); \
  }

#define PHP_PROTO_OBJECT_FREE_START(classname, lowername) \
  void lowername##_free(void* object TSRMLS_DC) {         \
    classname* intern = object;
#define PHP_PROTO_OBJECT_FREE_END                 \
    zend_object_std_dtor(&intern->std TSRMLS_CC); \
    efree(intern);                                \
  }

#define PHP_PROTO_OBJECT_DTOR_START(classname, lowername)
#define PHP_PROTO_OBJECT_DTOR_END

#define CACHED_VALUE zval*
#define CACHED_TO_ZVAL_PTR(VALUE) (VALUE)
#define CACHED_PTR_TO_ZVAL_PTR(VALUE) (*VALUE)
#define ZVAL_PTR_TO_CACHED_PTR(VALUE) (&VALUE)

#define CREATE_OBJ_ON_ALLOCATED_ZVAL_PTR(zval_ptr, class_type) \
  ZVAL_OBJ(zval_ptr, class_type->create_object(class_type TSRMLS_CC));

#define PHP_PROTO_SEPARATE_ZVAL_IF_NOT_REF(value) \
  SEPARATE_ZVAL_IF_NOT_REF(value)

#define PHP_PROTO_GLOBAL_UNINITIALIZED_ZVAL EG(uninitialized_zval_ptr)

#define OBJ_PROP(PROPERTIES, OFFSET) (PROPERTIES)->properties_table[OFFSET]

#define php_proto_zval_ptr_dtor(zval_ptr) \
  zval_ptr_dtor(&(zval_ptr))

#define PHP_PROTO_ALLOC_CLASS_OBJECT(class_object, class_type) \
  class_object* intern;                                        \
  intern = (class_object*)emalloc(sizeof(class_object));       \
  memset(intern, 0, sizeof(class_object));

#define PHP_PROTO_FREE_CLASS_OBJECT(class_object, class_object_free, handler) \
  zend_object_value retval = {0};                                             \
  retval.handle = zend_objects_store_put(                                     \
      intern, (zend_objects_store_dtor_t)zend_objects_destroy_object,         \
      class_object_free, NULL TSRMLS_CC);                                     \
  retval.handlers = handler;                                                  \
  return retval;

#define PHP_PROTO_ALLOC_ARRAY(zval_ptr)  \
  ALLOC_HASHTABLE(Z_ARRVAL_P(zval_ptr)); \
  Z_TYPE_P(zval_ptr) = IS_ARRAY;

#define ZVAL_OBJ(zval_ptr, call_create) \
  Z_TYPE_P(zval_ptr) = IS_OBJECT;       \
  Z_OBJVAL_P(zval_ptr) = call_create;

#define UNBOX(class_name, val) \
  (class_name*)zend_object_store_get_object(val TSRMLS_CC);

#define UNBOX_HASHTABLE_VALUE(class_name, val) UNBOX(class_name, val)

#define HASHTABLE_VALUE_DTOR ZVAL_PTR_DTOR

#define PHP_PROTO_HASHTABLE_VALUE zval*

#define CREATE_HASHTABLE_VALUE(OBJ, WRAPPED_OBJ, OBJ_TYPE, OBJ_CLASS_ENTRY) \
  OBJ_TYPE* OBJ;                                                            \
  PHP_PROTO_HASHTABLE_VALUE WRAPPED_OBJ;                                    \
  MAKE_STD_ZVAL(WRAPPED_OBJ);                                               \
  ZVAL_OBJ(WRAPPED_OBJ,                                                     \
           OBJ_CLASS_ENTRY->create_object(OBJ_CLASS_ENTRY TSRMLS_CC));      \
  OBJ = UNBOX_HASHTABLE_VALUE(OBJ_TYPE, WRAPPED_OBJ);                       \
  Z_DELREF_P(desc_php);

#define PHP_PROTO_CE_DECLARE zend_class_entry**
#define PHP_PROTO_CE_UNREF(ce) (*ce)

#define php_proto_zend_lookup_class(name, name_length, ce) \
  zend_lookup_class(name, name_length, ce TSRMLS_CC)

#else  // PHP_MAJOR_VERSION >= 7

#define php_proto_zend_literal void**
#define PHP_PROTO_CASE_IS_BOOL IS_TRUE: case IS_FALSE
#define PHP_PROTO_SIZE size_t
#define PHP_PROTO_LONG zend_long
#define PHP_PROTO_TSRMLS_DC
#define PHP_PROTO_TSRMLS_CC

// PHP String

#define PHP_PROTO_ZVAL_STRING(zval_ptr, s, copy) \
  ZVAL_STRING(zval_ptr, s)
#define PHP_PROTO_ZVAL_STRINGL(zval_ptr, s, len, copy) \
  ZVAL_STRINGL(zval_ptr, s, len)
#define PHP_PROTO_RETURN_STRING(s, copy) RETURN_STRING(s)
#define PHP_PROTO_RETURN_STRINGL(s, len, copy) RETURN_STRINGL(s, len)
#define PHP_PROTO_RETVAL_STRINGL(s, len, copy) RETVAL_STRINGL(s, len)
#define php_proto_zend_make_printable_zval(from, to) \
  zend_make_printable_zval(from, to)

// PHP Array

#define PHP_PROTO_HASH_OF(array) Z_ARRVAL_P(&array)

static inline int php_proto_zend_hash_index_update(HashTable* ht, ulong h,
                                                   void* pData, uint nDataSize,
                                                   void** pDest) {
  void* result = NULL;
  result = zend_hash_index_update_mem(ht, h, pData, nDataSize);
  if (pDest != NULL) *pDest = result;
  return result != NULL ? SUCCESS : FAILURE;
}

static inline int php_proto_zend_hash_index_find(const HashTable* ht, ulong h,
                                                 void** pDest) {
  void* result = NULL;
  result = zend_hash_index_find_ptr(ht, h);
  if (pDest != NULL) *pDest = result;
  return result != NULL ? SUCCESS : FAILURE;
}

static inline int php_proto_zend_hash_next_index_insert(HashTable* ht,
                                                        void* pData,
                                                        uint nDataSize,
                                                        void** pDest) {
  void* result = NULL;
  result = zend_hash_next_index_insert_mem(ht, pData, nDataSize);
  if (pDest != NULL) *pDest = result;
  return result != NULL ? SUCCESS : FAILURE;
}

static inline int php_proto_zend_hash_get_current_data_ex(HashTable* ht,
                                                          void** pDest,
                                                          HashPosition* pos) {
  void* result = NULL;
  result = zend_hash_get_current_data_ex(ht, pos);
  if (pDest != NULL) *pDest = result;
  return result != NULL ? SUCCESS : FAILURE;
}

// PHP Object

#define PHP_PROTO_WRAP_OBJECT_START(name) struct name {
#define PHP_PROTO_WRAP_OBJECT_END \
  zend_object std;                \
  };

#define PHP_PROTO_INIT_CLASS_START(CLASSNAME, CAMELNAME, LOWWERNAME)         \
  void LOWWERNAME##_init(TSRMLS_D) {                                         \
    zend_class_entry class_type;                                             \
    const char* class_name = CLASSNAME;                                      \
    INIT_CLASS_ENTRY_EX(class_type, CLASSNAME, strlen(CLASSNAME),            \
                        LOWWERNAME##_methods);                               \
    LOWWERNAME##_type = zend_register_internal_class(&class_type TSRMLS_CC); \
    LOWWERNAME##_type->create_object = LOWWERNAME##_create;                  \
    LOWWERNAME##_handlers = PEMALLOC(zend_object_handlers);                  \
    memcpy(LOWWERNAME##_handlers, zend_get_std_object_handlers(),            \
           sizeof(zend_object_handlers));                                    \
    LOWWERNAME##_handlers->free_obj = LOWWERNAME##_free;                     \
    LOWWERNAME##_handlers->dtor_obj = LOWWERNAME##_dtor;                     \
    LOWWERNAME##_handlers->offset = XtOffsetOf(CAMELNAME, std);
#define PHP_PROTO_INIT_CLASS_END \
  }

#define PHP_PROTO_OBJECT_FREE_START(classname, lowername) \
  void lowername##_free(zend_object* object) {            \
    classname* intern =                                   \
        (classname*)((char*)object - XtOffsetOf(classname, std));
#define PHP_PROTO_OBJECT_FREE_END           \
  }

#define PHP_PROTO_OBJECT_DTOR_START(classname, lowername) \
  void lowername##_dtor(zend_object* object) {            \
    classname* intern =                                   \
        (classname*)((char*)object - XtOffsetOf(classname, std));
#define PHP_PROTO_OBJECT_DTOR_END           \
    zend_object_std_dtor(object TSRMLS_CC); \
  }

#define PHP_PROTO_OBJECT_CREATE_START(NAME, LOWWERNAME)                     \
  static zend_object* LOWWERNAME##_create(zend_class_entry* ce TSRMLS_DC) { \
    PHP_PROTO_ALLOC_CLASS_OBJECT(NAME, ce);                                 \
    zend_object_std_init(&intern->std, ce TSRMLS_CC);                       \
    object_properties_init(&intern->std, ce);
#define PHP_PROTO_OBJECT_CREATE_END(NAME, LOWWERNAME)                          \
  PHP_PROTO_FREE_CLASS_OBJECT(NAME, LOWWERNAME##_free, LOWWERNAME##_handlers); \
  }

#define CACHED_VALUE zval
#define CACHED_TO_ZVAL_PTR(VALUE) (&VALUE)
#define CACHED_PTR_TO_ZVAL_PTR(VALUE) (VALUE)
#define ZVAL_PTR_TO_CACHED_PTR(VALUE) (VALUE)

#define CREATE_OBJ_ON_ALLOCATED_ZVAL_PTR(zval_ptr, class_type) \
  ZVAL_OBJ(zval_ptr, class_type->create_object(class_type));

#define PHP_PROTO_SEPARATE_ZVAL_IF_NOT_REF(value) ;

#define PHP_PROTO_GLOBAL_UNINITIALIZED_ZVAL &EG(uninitialized_zval)

#define php_proto_zval_ptr_dtor(zval_ptr) \
  zval_ptr_dtor(zval_ptr)

#define PHP_PROTO_ALLOC_CLASS_OBJECT(class_object, class_type)               \
  class_object* intern;                                                      \
  int size = sizeof(class_object) + zend_object_properties_size(class_type); \
  intern = ecalloc(1, size);                                                 \
  memset(intern, 0, size);

#define PHP_PROTO_FREE_CLASS_OBJECT(class_object, class_object_free, handler) \
  intern->std.handlers = handler;                                             \
  return &intern->std;

#define PHP_PROTO_ALLOC_ARRAY(zval_ptr) \
  ZVAL_NEW_ARR(zval_ptr)

#define UNBOX(class_name, val) \
  (class_name*)((char*)Z_OBJ_P(val) - XtOffsetOf(class_name, std));

#define UNBOX_HASHTABLE_VALUE(class_name, val) \
  (class_name*)((char*)val - XtOffsetOf(class_name, std))

#define HASHTABLE_VALUE_DTOR php_proto_hashtable_descriptor_release

#define PHP_PROTO_HASHTABLE_VALUE zend_object*

#define CREATE_HASHTABLE_VALUE(OBJ, WRAPPED_OBJ, OBJ_TYPE, OBJ_CLASS_ENTRY) \
  OBJ_TYPE* OBJ;                                                            \
  PHP_PROTO_HASHTABLE_VALUE WRAPPED_OBJ;                                    \
  WRAPPED_OBJ = OBJ_CLASS_ENTRY->create_object(OBJ_CLASS_ENTRY);            \
  OBJ = UNBOX_HASHTABLE_VALUE(OBJ_TYPE, WRAPPED_OBJ);                       \
  --GC_REFCOUNT(WRAPPED_OBJ);

#define PHP_PROTO_CE_DECLARE zend_class_entry*
#define PHP_PROTO_CE_UNREF(ce) (ce)

static inline int php_proto_zend_lookup_class(
    const char* name, int name_length, zend_class_entry** ce TSRMLS_DC) {
  zend_string *zstr_name = zend_string_init(name, name_length, 0);
  *ce = zend_lookup_class(zstr_name);
  zend_string_release(zstr_name);
  return *ce != NULL ? SUCCESS : FAILURE;
}

#endif  // PHP_MAJOR_VERSION >= 7

// -----------------------------------------------------------------------------
// Forward Declaration
// ----------------------------------------------------------------------------

struct DescriptorPool;
struct Descriptor;
struct EnumDescriptor;
struct FieldDescriptor;
struct MessageField;
struct MessageHeader;
struct MessageLayout;
struct RepeatedField;
struct RepeatedFieldIter;
struct Map;
struct MapIter;
struct Oneof;

typedef struct DescriptorPool DescriptorPool;
typedef struct Descriptor Descriptor;
typedef struct EnumDescriptor EnumDescriptor;
typedef struct FieldDescriptor FieldDescriptor;
typedef struct MessageField MessageField;
typedef struct MessageHeader MessageHeader;
typedef struct MessageLayout MessageLayout;
typedef struct RepeatedField RepeatedField;
typedef struct RepeatedFieldIter RepeatedFieldIter;
typedef struct Map Map;
typedef struct MapIter MapIter;
typedef struct Oneof Oneof;

// -----------------------------------------------------------------------------
// Globals.
// -----------------------------------------------------------------------------

ZEND_BEGIN_MODULE_GLOBALS(protobuf)
ZEND_END_MODULE_GLOBALS(protobuf)

// Init module and PHP classes.
void descriptor_init(TSRMLS_D);
void enum_descriptor_init(TSRMLS_D);
void descriptor_pool_init(TSRMLS_D);
void gpb_type_init(TSRMLS_D);
void map_field_init(TSRMLS_D);
void map_field_iter_init(TSRMLS_D);
void repeated_field_init(TSRMLS_D);
void repeated_field_iter_init(TSRMLS_D);
void util_init(TSRMLS_D);
void message_init(TSRMLS_D);

// Global map from upb {msg,enum}defs to wrapper Descriptor/EnumDescriptor
// instances.
void add_def_obj(const void* def, PHP_PROTO_HASHTABLE_VALUE value);
PHP_PROTO_HASHTABLE_VALUE get_def_obj(const void* def);

// Global map from PHP class entries to wrapper Descriptor/EnumDescriptor
// instances.
void add_ce_obj(const void* ce, PHP_PROTO_HASHTABLE_VALUE value);
PHP_PROTO_HASHTABLE_VALUE get_ce_obj(const void* ce);
bool class_added(const void* ce);

extern zend_class_entry* map_field_type;
extern zend_class_entry* repeated_field_type;

// -----------------------------------------------------------------------------
// Descriptor.
// -----------------------------------------------------------------------------

PHP_PROTO_WRAP_OBJECT_START(DescriptorPool)
  upb_symtab* symtab;
  HashTable* pending_list;
PHP_PROTO_WRAP_OBJECT_END

PHP_METHOD(DescriptorPool, getGeneratedPool);
PHP_METHOD(DescriptorPool, internalAddGeneratedFile);

// wrapper of generated pool
#if PHP_MAJOR_VERSION < 7
extern zval* generated_pool_php;
void descriptor_pool_free(void* object TSRMLS_DC);
#else
extern zend_object *generated_pool_php;
void descriptor_pool_free(zend_object* object);
#endif
extern DescriptorPool* generated_pool;  // The actual generated pool

PHP_PROTO_WRAP_OBJECT_START(Descriptor)
  const upb_msgdef* msgdef;
  MessageLayout* layout;
  zend_class_entry* klass;  // begins as NULL
  const upb_handlers* fill_handlers;
  const upb_pbdecodermethod* fill_method;
  const upb_json_parsermethod* json_fill_method;
  const upb_handlers* pb_serialize_handlers;
  const upb_handlers* json_serialize_handlers;
  const upb_handlers* json_serialize_handlers_preserve;
PHP_PROTO_WRAP_OBJECT_END

extern zend_class_entry* descriptor_type;

void descriptor_name_set(Descriptor *desc, const char *name);

PHP_PROTO_WRAP_OBJECT_START(FieldDescriptor)
  const upb_fielddef* fielddef;
PHP_PROTO_WRAP_OBJECT_END

PHP_PROTO_WRAP_OBJECT_START(EnumDescriptor)
  const upb_enumdef* enumdef;
  zend_class_entry* klass;  // begins as NULL
  // VALUE module;  // begins as nil
PHP_PROTO_WRAP_OBJECT_END

extern zend_class_entry* enum_descriptor_type;

// -----------------------------------------------------------------------------
// Message class creation.
// -----------------------------------------------------------------------------

void* message_data(MessageHeader* msg);
void custom_data_init(const zend_class_entry* ce,
                      MessageHeader* msg PHP_PROTO_TSRMLS_DC);

// Build PHP class for given descriptor. Instead of building from scratch, this
// function modifies existing class which has been partially defined in PHP
// code.
void build_class_from_descriptor(
    PHP_PROTO_HASHTABLE_VALUE php_descriptor TSRMLS_DC);

extern zend_object_handlers* message_handlers;

// -----------------------------------------------------------------------------
// Message layout / storage.
// -----------------------------------------------------------------------------

/*
 * In c extension, each protobuf message is a zval instance. The zval instance
 * is like union, which can be used to store int, string, zend_object_value and
 * etc. For protobuf message, the zval instance is used to store the
 * zend_object_value.
 *
 * The zend_object_value is composed of handlers and a handle to look up the
 * actual stored data. The handlers are pointers to functions, e.g., read,
 * write, and etc, to access properties.
 *
 * The actual data of protobuf messages is stored as MessageHeader in zend
 * engine's central repository. Each MessageHeader instance is composed of a
 * zend_object, a Descriptor instance and the real message data.
 *
 * For the reason that PHP's native types may not be large enough to store
 * protobuf message's field (e.g., int64), all message's data is stored in
 * custom memory layout and is indexed by the Descriptor instance.
 *
 * The zend_object contains the zend class entry and the properties table. The
 * zend class entry contains all information about protobuf message's
 * corresponding PHP class. The most useful information is the offset table of
 * properties. Because read access to properties requires returning zval
 * instance, we need to convert data from the custom layout to zval instance.
 * Instead of creating zval instance for every read access, we use the zval
 * instances in the properties table in the zend_object as cache.  When
 * accessing properties, the offset is needed to find the zval property in
 * zend_object's properties table. These properties will be updated using the
 * data from custom memory layout only when reading these properties.
 *
 * zval
 * |-zend_object_value obj
 *   |-zend_object_handlers* handlers -> |-read_property_handler
 *   |                                   |-write_property_handler
 *   |                              ++++++++++++++++++++++
 *   |-zend_object_handle handle -> + central repository +
 *                                  ++++++++++++++++++++++
 *  MessageHeader <-----------------|
 *  |-zend_object std
 *  | |-class_entry* ce -> class_entry
 *  | |                    |-HashTable properties_table (name->offset)
 *  | |-zval** properties_table <------------------------------|
 *  |                         |------> zval* property(cache)
 *  |-Descriptor* desc (name->offset)
 *  |-void** data <-----------|
 *           |-----------------------> void* property(data)
 *
 */

#define MESSAGE_FIELD_NO_CASE ((size_t)-1)

struct MessageField {
  size_t offset;
  int cache_index;  // Each field except oneof field has a zval cache to avoid
                    // multiple creation when being accessed.
  size_t case_offset;   // for oneofs, a uint32. Else, MESSAGE_FIELD_NO_CASE.
};

struct MessageLayout {
  const upb_msgdef* msgdef;
  MessageField* fields;
  size_t size;
};

PHP_PROTO_WRAP_OBJECT_START(MessageHeader)
  void* data;  // Point to the real message data.
               // Place needs to be consistent with map_parse_frame_data_t.
  Descriptor* descriptor;  // Kept alive by self.class.descriptor reference.
PHP_PROTO_WRAP_OBJECT_END

MessageLayout* create_layout(const upb_msgdef* msgdef);
void layout_init(MessageLayout* layout, void* storage,
                 CACHED_VALUE* properties_table PHP_PROTO_TSRMLS_DC);
zval* layout_get(MessageLayout* layout, const void* storage,
                 const upb_fielddef* field, CACHED_VALUE* cache TSRMLS_DC);
void layout_set(MessageLayout* layout, MessageHeader* header,
                const upb_fielddef* field, zval* val TSRMLS_DC);
void layout_merge(MessageLayout* layout, MessageHeader* from,
                  MessageHeader* to TSRMLS_DC);
const char* layout_get_oneof_case(MessageLayout* layout, const void* storage,
                                  const upb_oneofdef* oneof TSRMLS_DC);
void free_layout(MessageLayout* layout);

PHP_METHOD(Message, clear);
PHP_METHOD(Message, mergeFrom);
PHP_METHOD(Message, readOneof);
PHP_METHOD(Message, writeOneof);
PHP_METHOD(Message, whichOneof);
PHP_METHOD(Message, __construct);

// -----------------------------------------------------------------------------
// Encode / Decode.
// -----------------------------------------------------------------------------

// Maximum depth allowed during encoding, to avoid stack overflows due to
// cycles.
#define ENCODE_MAX_NESTING 63

// Constructs the upb decoder method for parsing messages of this type.
// This is called from the message class creation code.
const upb_pbdecodermethod *new_fillmsg_decodermethod(Descriptor *desc,
                                                     const void *owner);

PHP_METHOD(Message, serializeToString);
PHP_METHOD(Message, mergeFromString);
PHP_METHOD(Message, serializeToJsonString);
PHP_METHOD(Message, mergeFromJsonString);

// -----------------------------------------------------------------------------
// Type check / conversion.
// -----------------------------------------------------------------------------

bool protobuf_convert_to_int32(zval* from, int32_t* to);
bool protobuf_convert_to_uint32(zval* from, uint32_t* to);
bool protobuf_convert_to_int64(zval* from, int64_t* to);
bool protobuf_convert_to_uint64(zval* from, uint64_t* to);
bool protobuf_convert_to_float(zval* from, float* to);
bool protobuf_convert_to_double(zval* from, double* to);
bool protobuf_convert_to_bool(zval* from, int8_t* to);
bool protobuf_convert_to_string(zval* from);

PHP_METHOD(Util, checkInt32);
PHP_METHOD(Util, checkUint32);
PHP_METHOD(Util, checkInt64);
PHP_METHOD(Util, checkUint64);
PHP_METHOD(Util, checkEnum);
PHP_METHOD(Util, checkFloat);
PHP_METHOD(Util, checkDouble);
PHP_METHOD(Util, checkBool);
PHP_METHOD(Util, checkString);
PHP_METHOD(Util, checkBytes);
PHP_METHOD(Util, checkMessage);
PHP_METHOD(Util, checkMapField);
PHP_METHOD(Util, checkRepeatedField);

// -----------------------------------------------------------------------------
// Native slot storage abstraction.
// -----------------------------------------------------------------------------

#define NATIVE_SLOT_MAX_SIZE sizeof(uint64_t)

size_t native_slot_size(upb_fieldtype_t type);
bool native_slot_set(upb_fieldtype_t type, const zend_class_entry* klass,
                     void* memory, zval* value TSRMLS_DC);
// String/Message is stored differently in array/map from normal message fields.
// So we need to make a special method to handle that.
bool native_slot_set_by_array(upb_fieldtype_t type,
                              const zend_class_entry* klass, void* memory,
                              zval* value TSRMLS_DC);
void native_slot_init(upb_fieldtype_t type, void* memory, CACHED_VALUE* cache);
// For each property, in order to avoid conversion between the zval object and
// the actual data type during parsing/serialization, the containing message
// object use the custom memory layout to store the actual data type for each
// property inside of it.  To access a property from php code, the property
// needs to be converted to a zval object. The message object is not responsible
// for providing such a zval object. Instead the caller needs to provide one
// (cache) and update it with the actual data (memory).
void native_slot_get(upb_fieldtype_t type, const void* memory,
                     CACHED_VALUE* cache TSRMLS_DC);
// String/Message is stored differently in array/map from normal message fields.
// So we need to make a special method to handle that.
void native_slot_get_by_array(upb_fieldtype_t type, const void* memory,
                     CACHED_VALUE* cache TSRMLS_DC);
void native_slot_get_default(upb_fieldtype_t type,
                             CACHED_VALUE* cache TSRMLS_DC);

// -----------------------------------------------------------------------------
// Map Field.
// -----------------------------------------------------------------------------

extern zend_object_handlers* map_field_handlers;
extern zend_object_handlers* map_field_iter_handlers;

PHP_PROTO_WRAP_OBJECT_START(Map)
  upb_fieldtype_t key_type;
  upb_fieldtype_t value_type;
  const zend_class_entry* msg_ce;  // class entry for value message
  upb_strtable table;
PHP_PROTO_WRAP_OBJECT_END

PHP_PROTO_WRAP_OBJECT_START(MapIter)
  Map* self;
  upb_strtable_iter it;
PHP_PROTO_WRAP_OBJECT_END

void map_begin(zval* self, MapIter* iter TSRMLS_DC);
void map_next(MapIter* iter);
bool map_done(MapIter* iter);
const char* map_iter_key(MapIter* iter, int* len);
upb_value map_iter_value(MapIter* iter, int* len);

// These operate on a map-entry msgdef.
const upb_fielddef* map_entry_key(const upb_msgdef* msgdef);
const upb_fielddef* map_entry_value(const upb_msgdef* msgdef);

void map_field_create_with_field(const zend_class_entry* ce,
                                 const upb_fielddef* field,
                                 CACHED_VALUE* map_field PHP_PROTO_TSRMLS_DC);
void map_field_create_with_type(const zend_class_entry* ce,
                                upb_fieldtype_t key_type,
                                upb_fieldtype_t value_type,
                                const zend_class_entry* msg_ce,
                                CACHED_VALUE* map_field PHP_PROTO_TSRMLS_DC);
void* upb_value_memory(upb_value* v);

#define MAP_KEY_FIELD 1
#define MAP_VALUE_FIELD 2

// These operate on a map field (i.e., a repeated field of submessages whose
// submessage type is a map-entry msgdef).
bool is_map_field(const upb_fielddef* field);
const upb_fielddef* map_field_key(const upb_fielddef* field);
const upb_fielddef* map_field_value(const upb_fielddef* field);

bool map_index_set(Map *intern, const char* keyval, int length, upb_value v);

PHP_METHOD(MapField, __construct);
PHP_METHOD(MapField, offsetExists);
PHP_METHOD(MapField, offsetGet);
PHP_METHOD(MapField, offsetSet);
PHP_METHOD(MapField, offsetUnset);
PHP_METHOD(MapField, count);
PHP_METHOD(MapField, getIterator);

PHP_METHOD(MapFieldIter, rewind);
PHP_METHOD(MapFieldIter, current);
PHP_METHOD(MapFieldIter, key);
PHP_METHOD(MapFieldIter, next);
PHP_METHOD(MapFieldIter, valid);

// -----------------------------------------------------------------------------
// Repeated Field.
// -----------------------------------------------------------------------------

extern zend_object_handlers* repeated_field_handlers;
extern zend_object_handlers* repeated_field_iter_handlers;

PHP_PROTO_WRAP_OBJECT_START(RepeatedField)
#if PHP_MAJOR_VERSION < 7
  zval* array;
#else
  zval array;
#endif
  upb_fieldtype_t type;
  const zend_class_entry* msg_ce;  // class entry for containing message
                                   // (for message field only).
PHP_PROTO_WRAP_OBJECT_END

PHP_PROTO_WRAP_OBJECT_START(RepeatedFieldIter)
  RepeatedField* repeated_field;
  long position;
PHP_PROTO_WRAP_OBJECT_END

void repeated_field_create_with_field(
    zend_class_entry* ce, const upb_fielddef* field,
    CACHED_VALUE* repeated_field PHP_PROTO_TSRMLS_DC);
void repeated_field_create_with_type(
    zend_class_entry* ce, upb_fieldtype_t type, const zend_class_entry* msg_ce,
    CACHED_VALUE* repeated_field PHP_PROTO_TSRMLS_DC);
// Return the element at the index position from the repeated field. There is
// not restriction on the type of stored elements.
void *repeated_field_index_native(RepeatedField *intern, int index TSRMLS_DC);
// Add the element to the end of the repeated field. There is not restriction on
// the type of stored elements.
void repeated_field_push_native(RepeatedField *intern, void *value);

PHP_METHOD(RepeatedField, __construct);
PHP_METHOD(RepeatedField, append);
PHP_METHOD(RepeatedField, offsetExists);
PHP_METHOD(RepeatedField, offsetGet);
PHP_METHOD(RepeatedField, offsetSet);
PHP_METHOD(RepeatedField, offsetUnset);
PHP_METHOD(RepeatedField, count);
PHP_METHOD(RepeatedField, getIterator);

PHP_METHOD(RepeatedFieldIter, rewind);
PHP_METHOD(RepeatedFieldIter, current);
PHP_METHOD(RepeatedFieldIter, key);
PHP_METHOD(RepeatedFieldIter, next);
PHP_METHOD(RepeatedFieldIter, valid);

// -----------------------------------------------------------------------------
// Oneof Field.
// -----------------------------------------------------------------------------

PHP_PROTO_WRAP_OBJECT_START(Oneof)
  upb_oneofdef* oneofdef;
  int index;    // Index of field in oneof. -1 if not set.
  char value[NATIVE_SLOT_MAX_SIZE];
PHP_PROTO_WRAP_OBJECT_END

// Oneof case slot value to indicate that no oneof case is set. The value `0` is
// safe because field numbers are used as case identifiers, and no field can
// have a number of 0.
#define ONEOF_CASE_NONE 0

// -----------------------------------------------------------------------------
// Upb.
// -----------------------------------------------------------------------------

upb_fieldtype_t to_fieldtype(upb_descriptortype_t type);
const zend_class_entry* field_type_class(
    const upb_fielddef* field PHP_PROTO_TSRMLS_DC);

// -----------------------------------------------------------------------------
// Utilities.
// -----------------------------------------------------------------------------

// Memory management
#define ALLOC(class_name) (class_name*) emalloc(sizeof(class_name))
#define PEMALLOC(class_name) (class_name*) pemalloc(sizeof(class_name), 1)
#define ALLOC_N(class_name, n) (class_name*) emalloc(sizeof(class_name) * n)
#define FREE(object) efree(object)
#define PEFREE(object) pefree(object, 1)

// String argument.
#define STR(str) (str), strlen(str)

// Zend Value
#if PHP_MAJOR_VERSION < 7
#define Z_OBJ_P(zval_p)                                       \
  ((zend_object*)(EG(objects_store)                           \
                      .object_buckets[Z_OBJ_HANDLE_P(zval_p)] \
                      .bucket.obj.object))
#endif

#endif  // __GOOGLE_PROTOBUF_PHP_PROTOBUF_H__

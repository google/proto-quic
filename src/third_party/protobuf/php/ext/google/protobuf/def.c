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

#include "protobuf.h"

const char* const kReservedNames[] = {"Empty", "ECHO", "ARRAY"};
const int kReservedNamesSize = 3;

// Forward declare.
static void descriptor_init_c_instance(Descriptor* intern TSRMLS_DC);
static void descriptor_free_c(Descriptor* object TSRMLS_DC);

static void enum_descriptor_init_c_instance(EnumDescriptor* intern TSRMLS_DC);
static void enum_descriptor_free_c(EnumDescriptor* object TSRMLS_DC);

static void descriptor_pool_free_c(DescriptorPool* object TSRMLS_DC);
static void descriptor_pool_init_c_instance(DescriptorPool* pool TSRMLS_DC);

// -----------------------------------------------------------------------------
// Common Utilities
// -----------------------------------------------------------------------------

static void check_upb_status(const upb_status* status, const char* msg) {
  if (!upb_ok(status)) {
    zend_error(E_ERROR, "%s: %s\n", msg, upb_status_errmsg(status));
  }
}

static void upb_filedef_free(void *r) {
  upb_filedef *f = *(upb_filedef **)r;
  size_t i;

  for (i = 0; i < upb_filedef_depcount(f); i++) {
    upb_filedef_unref(upb_filedef_dep(f, i), f);
  }

  upb_inttable_uninit(&f->defs);
  upb_inttable_uninit(&f->deps);
  upb_gfree((void *)f->name);
  upb_gfree((void *)f->package);
  upb_gfree(f);
}

// Camel-case the field name and append "Entry" for generated map entry name.
// e.g. map<KeyType, ValueType> foo_map => FooMapEntry
static void append_map_entry_name(char *result, const char *field_name,
                                  int pos) {
  bool cap_next = true;
  int i;

  for (i = 0; i < strlen(field_name); ++i) {
    if (field_name[i] == '_') {
      cap_next = true;
    } else if (cap_next) {
      // Note: Do not use ctype.h due to locales.
      if ('a' <= field_name[i] && field_name[i] <= 'z') {
        result[pos++] = field_name[i] - 'a' + 'A';
      } else {
        result[pos++] = field_name[i];
      }
      cap_next = false;
    } else {
      result[pos++] = field_name[i];
    }
  }
  strcat(result, "Entry");
}

#define CHECK_UPB(code, msg)             \
  do {                                   \
    upb_status status = UPB_STATUS_INIT; \
    code;                                \
    check_upb_status(&status, msg);      \
  } while (0)

// Define PHP class
#define DEFINE_PROTOBUF_INIT_CLASS(CLASSNAME, CAMELNAME, LOWERNAME) \
  PHP_PROTO_INIT_CLASS_START(CLASSNAME, CAMELNAME, LOWERNAME)       \
  PHP_PROTO_INIT_CLASS_END

#define DEFINE_PROTOBUF_CREATE(NAME, LOWERNAME)  \
  PHP_PROTO_OBJECT_CREATE_START(NAME, LOWERNAME) \
  LOWERNAME##_init_c_instance(intern TSRMLS_CC); \
  PHP_PROTO_OBJECT_CREATE_END(NAME, LOWERNAME)

#define DEFINE_PROTOBUF_FREE(CAMELNAME, LOWERNAME)  \
  PHP_PROTO_OBJECT_FREE_START(CAMELNAME, LOWERNAME) \
  LOWERNAME##_free_c(intern TSRMLS_CC);             \
  PHP_PROTO_OBJECT_FREE_END

#define DEFINE_PROTOBUF_DTOR(CAMELNAME, LOWERNAME)  \
  PHP_PROTO_OBJECT_DTOR_START(CAMELNAME, LOWERNAME) \
  PHP_PROTO_OBJECT_DTOR_END

#define DEFINE_CLASS(NAME, LOWERNAME, string_name) \
  zend_class_entry *LOWERNAME##_type;              \
  zend_object_handlers *LOWERNAME##_handlers;      \
  DEFINE_PROTOBUF_FREE(NAME, LOWERNAME)            \
  DEFINE_PROTOBUF_DTOR(NAME, LOWERNAME)            \
  DEFINE_PROTOBUF_CREATE(NAME, LOWERNAME)          \
  DEFINE_PROTOBUF_INIT_CLASS(string_name, NAME, LOWERNAME)

// -----------------------------------------------------------------------------
// GPBType
// -----------------------------------------------------------------------------

zend_class_entry* gpb_type_type;

static zend_function_entry gpb_type_methods[] = {
  ZEND_FE_END
};

void gpb_type_init(TSRMLS_D) {
  zend_class_entry class_type;
  INIT_CLASS_ENTRY(class_type, "Google\\Protobuf\\Internal\\GPBType",
                   gpb_type_methods);
  gpb_type_type = zend_register_internal_class(&class_type TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("DOUBLE"),  1 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("FLOAT"),   2 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("INT64"),   3 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("UINT64"),  4 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("INT32"),   5 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("FIXED64"), 6 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("FIXED32"), 7 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("BOOL"),    8 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("STRING"),  9 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("GROUP"),   10 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("MESSAGE"), 11 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("BYTES"),   12 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("UINT32"),  13 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("ENUM"),    14 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("SFIXED32"),
                                   15 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("SFIXED64"),
                                   16 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("SINT32"), 17 TSRMLS_CC);
  zend_declare_class_constant_long(gpb_type_type, STR("SINT64"), 18 TSRMLS_CC);
}

// -----------------------------------------------------------------------------
// Descriptor
// -----------------------------------------------------------------------------

static zend_function_entry descriptor_methods[] = {
  ZEND_FE_END
};

DEFINE_CLASS(Descriptor, descriptor, "Google\\Protobuf\\Internal\\Descriptor");

static void descriptor_free_c(Descriptor *self TSRMLS_DC) {
  if (self->layout) {
    free_layout(self->layout);
  }
  if (self->fill_handlers) {
    upb_handlers_unref(self->fill_handlers, &self->fill_handlers);
  }
  if (self->fill_method) {
    upb_pbdecodermethod_unref(self->fill_method, &self->fill_method);
  }
  if (self->json_fill_method) {
    upb_json_parsermethod_unref(self->json_fill_method,
                                &self->json_fill_method);
  }
  if (self->pb_serialize_handlers) {
    upb_handlers_unref(self->pb_serialize_handlers,
                       &self->pb_serialize_handlers);
  }
  if (self->json_serialize_handlers) {
    upb_handlers_unref(self->json_serialize_handlers,
                       &self->json_serialize_handlers);
  }
  if (self->json_serialize_handlers_preserve) {
    upb_handlers_unref(self->json_serialize_handlers_preserve,
                       &self->json_serialize_handlers_preserve);
  }
}

static void descriptor_init_c_instance(Descriptor *desc TSRMLS_DC) {
  // zend_object_std_init(&desc->std, descriptor_type TSRMLS_CC);
  desc->msgdef = NULL;
  desc->layout = NULL;
  desc->klass = NULL;
  desc->fill_handlers = NULL;
  desc->fill_method = NULL;
  desc->json_fill_method = NULL;
  desc->pb_serialize_handlers = NULL;
  desc->json_serialize_handlers = NULL;
  desc->json_serialize_handlers_preserve = NULL;
}

// -----------------------------------------------------------------------------
// EnumDescriptor
// -----------------------------------------------------------------------------

static zend_function_entry enum_descriptor_methods[] = {
  ZEND_FE_END
};

DEFINE_CLASS(EnumDescriptor, enum_descriptor,
             "Google\\Protobuf\\Internal\\EnumDescriptor");

static void enum_descriptor_free_c(EnumDescriptor *self TSRMLS_DC) {
}

static void enum_descriptor_init_c_instance(EnumDescriptor *self TSRMLS_DC) {
  // zend_object_std_init(&self->std, enum_descriptor_type TSRMLS_CC);
  self->enumdef = NULL;
  self->klass = NULL;
}

// -----------------------------------------------------------------------------
// FieldDescriptor
// -----------------------------------------------------------------------------

upb_fieldtype_t to_fieldtype(upb_descriptortype_t type) {
  switch (type) {
#define CASE(descriptor_type, type)           \
  case UPB_DESCRIPTOR_TYPE_##descriptor_type: \
    return UPB_TYPE_##type;

  CASE(FLOAT,    FLOAT);
  CASE(DOUBLE,   DOUBLE);
  CASE(BOOL,     BOOL);
  CASE(STRING,   STRING);
  CASE(BYTES,    BYTES);
  CASE(MESSAGE,  MESSAGE);
  CASE(GROUP,    MESSAGE);
  CASE(ENUM,     ENUM);
  CASE(INT32,    INT32);
  CASE(INT64,    INT64);
  CASE(UINT32,   UINT32);
  CASE(UINT64,   UINT64);
  CASE(SINT32,   INT32);
  CASE(SINT64,   INT64);
  CASE(FIXED32,  UINT32);
  CASE(FIXED64,  UINT64);
  CASE(SFIXED32, INT32);
  CASE(SFIXED64, INT64);

#undef CONVERT

  }

  zend_error(E_ERROR, "Unknown field type.");
  return 0;
}

// -----------------------------------------------------------------------------
// DescriptorPool
// -----------------------------------------------------------------------------

static zend_function_entry descriptor_pool_methods[] = {
  PHP_ME(DescriptorPool, getGeneratedPool, NULL,
         ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
  PHP_ME(DescriptorPool, internalAddGeneratedFile, NULL, ZEND_ACC_PUBLIC)
  ZEND_FE_END
};

DEFINE_CLASS(DescriptorPool, descriptor_pool,
             "Google\\Protobuf\\Internal\\DescriptorPool");

// wrapper of generated pool
#if PHP_MAJOR_VERSION < 7
zval* generated_pool_php;
#else
zend_object *generated_pool_php;
#endif
DescriptorPool *generated_pool;  // The actual generated pool

static void init_generated_pool_once(TSRMLS_D) {
  if (generated_pool_php == NULL) {
#if PHP_MAJOR_VERSION < 7
    MAKE_STD_ZVAL(generated_pool_php);
    ZVAL_OBJ(generated_pool_php, descriptor_pool_type->create_object(
                                     descriptor_pool_type TSRMLS_CC));
    generated_pool = UNBOX(DescriptorPool, generated_pool_php);
#else
    generated_pool_php =
        descriptor_pool_type->create_object(descriptor_pool_type TSRMLS_CC);
    generated_pool = (DescriptorPool *)((char *)generated_pool_php -
                                        XtOffsetOf(DescriptorPool, std));
#endif
  }
}

static void descriptor_pool_init_c_instance(DescriptorPool *pool TSRMLS_DC) {
  // zend_object_std_init(&pool->std, descriptor_pool_type TSRMLS_CC);
  pool->symtab = upb_symtab_new();

  ALLOC_HASHTABLE(pool->pending_list);
  zend_hash_init(pool->pending_list, 1, NULL, ZVAL_PTR_DTOR, 0);
}

static void descriptor_pool_free_c(DescriptorPool *pool TSRMLS_DC) {
  upb_symtab_free(pool->symtab);

  zend_hash_destroy(pool->pending_list);
  FREE_HASHTABLE(pool->pending_list);
}

static void validate_enumdef(const upb_enumdef *enumdef) {
  // Verify that an entry exists with integer value 0. (This is the default
  // value.)
  const char *lookup = upb_enumdef_iton(enumdef, 0);
  if (lookup == NULL) {
    zend_error(E_USER_ERROR,
               "Enum definition does not contain a value for '0'.");
  }
}

static void validate_msgdef(const upb_msgdef* msgdef) {
  // Verify that no required fields exist. proto3 does not support these.
  upb_msg_field_iter it;
  for (upb_msg_field_begin(&it, msgdef);
       !upb_msg_field_done(&it);
       upb_msg_field_next(&it)) {
    const upb_fielddef* field = upb_msg_iter_field(&it);
    if (upb_fielddef_label(field) == UPB_LABEL_REQUIRED) {
      zend_error(E_ERROR, "Required fields are unsupported in proto3.");
    }
  }
}

PHP_METHOD(DescriptorPool, getGeneratedPool) {
  init_generated_pool_once(TSRMLS_C);
#if PHP_MAJOR_VERSION < 7
  RETURN_ZVAL(generated_pool_php, 1, 0);
#else
  ++GC_REFCOUNT(generated_pool_php);
  RETURN_OBJ(generated_pool_php);
#endif
}

static void classname_no_prefix(const char *fullname, const char *package_name,
                                char *class_name) {
  size_t i = 0, j;
  bool first_char = true, is_reserved = false;
  size_t pkg_name_len = package_name == NULL ? 0 : strlen(package_name);
  size_t message_name_start = package_name == NULL ? 0 : pkg_name_len + 1;
  size_t message_len = (strlen(fullname) - message_name_start);

  // Submessage is concatenated with its containing messages by '_'.
  for (j = message_name_start; j < message_name_start + message_len; j++) {
    if (fullname[j] == '.') {
      class_name[i++] = '_';
    } else {
      class_name[i++] = fullname[j];
    }
  }
}

static const char *classname_prefix(const char *classname,
                                    const char *prefix_given,
                                    const char *package_name) {
  size_t i;
  bool is_reserved = false;

  if (prefix_given != NULL && strcmp(prefix_given, "") != 0) {
    return prefix_given;
  }

  for (i = 0; i < kReservedNamesSize; i++) {
    if (strcmp(kReservedNames[i], classname) == 0) {
      is_reserved = true;
      break;
    }
  }

  if (is_reserved) {
    if (package_name != NULL && strcmp("google.protobuf", package_name) == 0) {
      return "GPB";
    } else {
      return "PB";
    }
  }

  return "";
}

static void convert_to_class_name_inplace(const char *package,
                                          const char *namespace_given,
                                          const char *prefix, char *classname) {
  size_t prefix_len = prefix == NULL ? 0 : strlen(prefix);
  size_t classname_len = strlen(classname);
  int i = 0, j;
  bool first_char = true;

  size_t package_len = package == NULL ? 0 : strlen(package);
  size_t namespace_given_len =
      namespace_given == NULL ? 0 : strlen(namespace_given);
  bool use_namespace_given = namespace_given != NULL;
  size_t namespace_len =
      use_namespace_given ? namespace_given_len : package_len;

  int offset = namespace_len != 0 ? 2 : 0;

  for (j = 0; j < classname_len; j++) {
    classname[namespace_len + prefix_len + classname_len + offset - 1 - j] =
        classname[classname_len - j - 1];
  }

  if (namespace_len != 0) {
    classname[i++] = '\\';
    for (j = 0; j < namespace_len; j++) {
      if (use_namespace_given) {
        classname[i++] = namespace_given[j];
        continue;
      }
      // php packages are divided by '\'.
      if (package[j] == '.') {
        classname[i++] = '\\';
        first_char = true;
      } else if (first_char) {
        // PHP package uses camel case.
        if (package[j] < 'A' || package[j] > 'Z') {
          classname[i++] = package[j] + 'A' - 'a';
        } else {
          classname[i++] = package[j];
        }
        first_char = false;
      } else {
        classname[i++] = package[j];
      }
    }
    classname[i++] = '\\';
  }

  memcpy(classname + i, prefix, prefix_len);
}

PHP_METHOD(DescriptorPool, internalAddGeneratedFile) {
  char *data = NULL;
  PHP_PROTO_SIZE data_len;
  upb_filedef **files;
  size_t i;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) ==
      FAILURE) {
    return;
  }

  DescriptorPool *pool = UNBOX(DescriptorPool, getThis());
  CHECK_UPB(files = upb_loaddescriptor(data, data_len, &pool, &status),
            "Parse binary descriptors to internal descriptors failed");

  // This method is called only once in each file.
  assert(files[0] != NULL);
  assert(files[1] == NULL);

  CHECK_UPB(upb_symtab_addfile(pool->symtab, files[0], &status),
            "Unable to add file to DescriptorPool");

  // For each enum/message, we need its PHP class, upb descriptor and its PHP
  // wrapper. These information are needed later for encoding, decoding and type
  // checking. However, sometimes we just have one of them. In order to find
  // them quickly, here, we store the mapping for them.
  for (i = 0; i < upb_filedef_defcount(files[0]); i++) {
    const upb_def *def = upb_filedef_def(files[0], i);
    switch (upb_def_type(def)) {
#define CASE_TYPE(def_type, def_type_lower, desc_type, desc_type_lower)        \
  case UPB_DEF_##def_type: {                                                   \
    CREATE_HASHTABLE_VALUE(desc, desc_php, desc_type, desc_type_lower##_type); \
    const upb_##def_type_lower *def_type_lower =                               \
        upb_downcast_##def_type_lower(def);                                    \
    desc->def_type_lower = def_type_lower;                                     \
    add_def_obj(desc->def_type_lower, desc_php);                               \
    /* Unlike other messages, MapEntry is shared by all map fields and doesn't \
     * have generated PHP class.*/                                             \
    if (upb_def_type(def) == UPB_DEF_MSG &&                                    \
        upb_msgdef_mapentry(upb_downcast_msgdef(def))) {                       \
      break;                                                                   \
    }                                                                          \
    /* Prepend '.' to package name to make it absolute. In the 5 additional    \
     * bytes allocated, one for '.', one for trailing 0, and 3 for 'GPB' if    \
     * given message is google.protobuf.Empty.*/                               \
    const char *fullname = upb_##def_type_lower##_fullname(def_type_lower);    \
    const char *php_namespace = upb_filedef_phpnamespace(files[0]);            \
    const char *prefix_given = upb_filedef_phpprefix(files[0]);                \
    size_t classname_len = strlen(fullname) + 5;                               \
    if (prefix_given != NULL) {                                                \
      classname_len += strlen(prefix_given);                                   \
    }                                                                          \
    if (php_namespace != NULL) {                                               \
      classname_len += strlen(php_namespace);                                  \
    }                                                                          \
    char *classname = ecalloc(sizeof(char), classname_len);                    \
    const char *package = upb_filedef_package(files[0]);                       \
    classname_no_prefix(fullname, package, classname);                         \
    const char *prefix = classname_prefix(classname, prefix_given, package);   \
    convert_to_class_name_inplace(package, php_namespace, prefix, classname);  \
    PHP_PROTO_CE_DECLARE pce;                                                  \
    if (php_proto_zend_lookup_class(classname, strlen(classname), &pce) ==     \
        FAILURE) {                                                             \
      zend_error(E_ERROR, "Generated message class %s hasn't been defined",    \
                 classname);                                                   \
      return;                                                                  \
    } else {                                                                   \
      desc->klass = PHP_PROTO_CE_UNREF(pce);                                   \
    }                                                                          \
    add_ce_obj(desc->klass, desc_php);                                         \
    efree(classname);                                                          \
    break;                                                                     \
  }

      CASE_TYPE(MSG, msgdef, Descriptor, descriptor)
      CASE_TYPE(ENUM, enumdef, EnumDescriptor, enum_descriptor)
#undef CASE_TYPE

      default:
        break;
    }
  }

  for (i = 0; i < upb_filedef_defcount(files[0]); i++) {
    const upb_def *def = upb_filedef_def(files[0], i);
    if (upb_def_type(def) == UPB_DEF_MSG) {
      const upb_msgdef *msgdef = upb_downcast_msgdef(def);
      PHP_PROTO_HASHTABLE_VALUE desc_php = get_def_obj(msgdef);
      build_class_from_descriptor(desc_php TSRMLS_CC);
    }
  }

  upb_filedef_unref(files[0], &pool);
  upb_gfree(files);
}

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/values.h"

#include <string.h>

#include <algorithm>
#include <cmath>
#include <ostream>
#include <utility>

#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"

namespace base {

namespace {

const char* const kTypeNames[] = {"null",   "boolean", "integer",    "double",
                                  "string", "binary",  "dictionary", "list"};
static_assert(arraysize(kTypeNames) ==
                  static_cast<size_t>(Value::Type::LIST) + 1,
              "kTypeNames Has Wrong Size");

std::unique_ptr<Value> CopyWithoutEmptyChildren(const Value& node);

// Make a deep copy of |node|, but don't include empty lists or dictionaries
// in the copy. It's possible for this function to return NULL and it
// expects |node| to always be non-NULL.
std::unique_ptr<ListValue> CopyListWithoutEmptyChildren(const ListValue& list) {
  std::unique_ptr<ListValue> copy;
  for (const auto& entry : list) {
    std::unique_ptr<Value> child_copy = CopyWithoutEmptyChildren(*entry);
    if (child_copy) {
      if (!copy)
        copy.reset(new ListValue);
      copy->Append(std::move(child_copy));
    }
  }
  return copy;
}

std::unique_ptr<DictionaryValue> CopyDictionaryWithoutEmptyChildren(
    const DictionaryValue& dict) {
  std::unique_ptr<DictionaryValue> copy;
  for (DictionaryValue::Iterator it(dict); !it.IsAtEnd(); it.Advance()) {
    std::unique_ptr<Value> child_copy = CopyWithoutEmptyChildren(it.value());
    if (child_copy) {
      if (!copy)
        copy.reset(new DictionaryValue);
      copy->SetWithoutPathExpansion(it.key(), std::move(child_copy));
    }
  }
  return copy;
}

std::unique_ptr<Value> CopyWithoutEmptyChildren(const Value& node) {
  switch (node.GetType()) {
    case Value::Type::LIST:
      return CopyListWithoutEmptyChildren(static_cast<const ListValue&>(node));

    case Value::Type::DICTIONARY:
      return CopyDictionaryWithoutEmptyChildren(
          static_cast<const DictionaryValue&>(node));

    default:
      return node.CreateDeepCopy();
  }
}

}  // namespace

// static
std::unique_ptr<Value> Value::CreateNullValue() {
  return WrapUnique(new Value(Type::NONE));
}

// static
std::unique_ptr<BinaryValue> BinaryValue::CreateWithCopiedBuffer(
    const char* buffer,
    size_t size) {
  return MakeUnique<BinaryValue>(std::vector<char>(buffer, buffer + size));
}

Value::Value(const Value& that) {
  InternalCopyConstructFrom(that);
}

Value::Value(Value&& that) {
  InternalMoveConstructFrom(std::move(that));
}

Value::Value() : type_(Type::NONE) {}

Value::Value(Type type) : type_(type) {
  // Initialize with the default value.
  switch (type_) {
    case Type::NONE:
      return;

    case Type::BOOLEAN:
      bool_value_ = false;
      return;
    case Type::INTEGER:
      int_value_ = 0;
      return;
    case Type::DOUBLE:
      double_value_ = 0.0;
      return;
    case Type::STRING:
      string_value_.Init();
      return;
    case Type::BINARY:
      binary_value_.Init();
      return;
    case Type::DICTIONARY:
      dict_ptr_.Init(MakeUnique<DictStorage>());
      return;
    case Type::LIST:
      list_.Init();
      return;
  }
}

Value::Value(bool in_bool) : type_(Type::BOOLEAN), bool_value_(in_bool) {}

Value::Value(int in_int) : type_(Type::INTEGER), int_value_(in_int) {}

Value::Value(double in_double) : type_(Type::DOUBLE), double_value_(in_double) {
  if (!std::isfinite(double_value_)) {
    NOTREACHED() << "Non-finite (i.e. NaN or positive/negative infinity) "
                 << "values cannot be represented in JSON";
    double_value_ = 0.0;
  }
}

Value::Value(const char* in_string) : type_(Type::STRING) {
  string_value_.Init(in_string);
  DCHECK(IsStringUTF8(*string_value_));
}

Value::Value(const std::string& in_string) : type_(Type::STRING) {
  string_value_.Init(in_string);
  DCHECK(IsStringUTF8(*string_value_));
}

Value::Value(std::string&& in_string) : type_(Type::STRING) {
  string_value_.Init(std::move(in_string));
  DCHECK(IsStringUTF8(*string_value_));
}

Value::Value(const char16* in_string) : type_(Type::STRING) {
  string_value_.Init(UTF16ToUTF8(in_string));
}

Value::Value(const string16& in_string) : type_(Type::STRING) {
  string_value_.Init(UTF16ToUTF8(in_string));
}

Value::Value(StringPiece in_string) : Value(in_string.as_string()) {}

Value::Value(const std::vector<char>& in_blob) : type_(Type::BINARY) {
  binary_value_.Init(in_blob);
}

Value::Value(std::vector<char>&& in_blob) : type_(Type::BINARY) {
  binary_value_.Init(std::move(in_blob));
}

Value& Value::operator=(const Value& that) {
  if (this != &that) {
    if (type_ == that.type_) {
      InternalCopyAssignFrom(that);
    } else {
      InternalCleanup();
      InternalCopyConstructFrom(that);
    }
  }

  return *this;
}

Value& Value::operator=(Value&& that) {
  if (this != &that) {
    if (type_ == that.type_) {
      InternalMoveAssignFrom(std::move(that));
    } else {
      InternalCleanup();
      InternalMoveConstructFrom(std::move(that));
    }
  }

  return *this;
}

Value::~Value() {
  InternalCleanup();
}

// static
const char* Value::GetTypeName(Value::Type type) {
  DCHECK_GE(static_cast<int>(type), 0);
  DCHECK_LT(static_cast<size_t>(type), arraysize(kTypeNames));
  return kTypeNames[static_cast<size_t>(type)];
}

bool Value::GetBool() const {
  CHECK(is_bool());
  return bool_value_;
}

int Value::GetInt() const {
  CHECK(is_int());
  return int_value_;
}

double Value::GetDouble() const {
  if (is_double())
    return double_value_;
  if (is_int())
    return int_value_;
  CHECK(false);
  return 0.0;
}

const std::string& Value::GetString() const {
  CHECK(is_string());
  return *string_value_;
}

const std::vector<char>& Value::GetBlob() const {
  CHECK(is_blob());
  return *binary_value_;
}

size_t Value::GetSize() const {
  return GetBlob().size();
}

const char* Value::GetBuffer() const {
  return GetBlob().data();
}

bool Value::GetAsBoolean(bool* out_value) const {
  if (out_value && is_bool()) {
    *out_value = bool_value_;
    return true;
  }
  return is_bool();
}

bool Value::GetAsInteger(int* out_value) const {
  if (out_value && is_int()) {
    *out_value = int_value_;
    return true;
  }
  return is_int();
}

bool Value::GetAsDouble(double* out_value) const {
  if (out_value && is_double()) {
    *out_value = double_value_;
    return true;
  } else if (out_value && is_int()) {
    // Allow promotion from int to double.
    *out_value = int_value_;
    return true;
  }
  return is_double() || is_int();
}

bool Value::GetAsString(std::string* out_value) const {
  if (out_value && is_string()) {
    *out_value = *string_value_;
    return true;
  }
  return is_string();
}

bool Value::GetAsString(string16* out_value) const {
  if (out_value && is_string()) {
    *out_value = UTF8ToUTF16(*string_value_);
    return true;
  }
  return is_string();
}

bool Value::GetAsString(const StringValue** out_value) const {
  if (out_value && is_string()) {
    *out_value = static_cast<const StringValue*>(this);
    return true;
  }
  return is_string();
}

bool Value::GetAsString(StringPiece* out_value) const {
  if (out_value && is_string()) {
    *out_value = *string_value_;
    return true;
  }
  return is_string();
}

bool Value::GetAsBinary(const BinaryValue** out_value) const {
  if (out_value && is_blob()) {
    *out_value = this;
    return true;
  }
  return is_blob();
}

bool Value::GetAsList(ListValue** out_value) {
  if (out_value && is_list()) {
    *out_value = static_cast<ListValue*>(this);
    return true;
  }
  return is_list();
}

bool Value::GetAsList(const ListValue** out_value) const {
  if (out_value && is_list()) {
    *out_value = static_cast<const ListValue*>(this);
    return true;
  }
  return is_list();
}

bool Value::GetAsDictionary(DictionaryValue** out_value) {
  if (out_value && is_dict()) {
    *out_value = static_cast<DictionaryValue*>(this);
    return true;
  }
  return is_dict();
}

bool Value::GetAsDictionary(const DictionaryValue** out_value) const {
  if (out_value && is_dict()) {
    *out_value = static_cast<const DictionaryValue*>(this);
    return true;
  }
  return is_dict();
}

Value* Value::DeepCopy() const {
  // This method should only be getting called for null Values--all subclasses
  // need to provide their own implementation;.
  switch (type()) {
    case Type::NONE:
      return CreateNullValue().release();

    case Type::BOOLEAN:
      return new Value(bool_value_);
    case Type::INTEGER:
      return new Value(int_value_);
    case Type::DOUBLE:
      return new Value(double_value_);
    // For now, make StringValues for backward-compatibility. Convert to
    // Value when that code is deleted.
    case Type::STRING:
      return new StringValue(*string_value_);
    // For now, make BinaryValues for backward-compatibility. Convert to
    // Value when that code is deleted.
    case Type::BINARY:
      return new BinaryValue(*binary_value_);

    // TODO(crbug.com/646113): Clean this up when DictionaryValue and ListValue
    // are completely inlined.
    case Type::DICTIONARY: {
      DictionaryValue* result = new DictionaryValue;

      for (const auto& current_entry : **dict_ptr_) {
        result->SetWithoutPathExpansion(current_entry.first,
                                        current_entry.second->CreateDeepCopy());
      }

      return result;
    }

    case Type::LIST: {
      ListValue* result = new ListValue;

      for (const auto& entry : *list_)
        result->Append(entry->CreateDeepCopy());

      return result;
    }

    default:
      NOTREACHED();
      return nullptr;
  }
}

std::unique_ptr<Value> Value::CreateDeepCopy() const {
  return WrapUnique(DeepCopy());
}

bool Value::Equals(const Value* other) const {
  if (other->type() != type())
    return false;

  switch (type()) {
    case Type::NONE:
      return true;
    case Type::BOOLEAN:
      return bool_value_ == other->bool_value_;
    case Type::INTEGER:
      return int_value_ == other->int_value_;
    case Type::DOUBLE:
      return double_value_ == other->double_value_;
    case Type::STRING:
      return *string_value_ == *(other->string_value_);
    case Type::BINARY:
      return *binary_value_ == *(other->binary_value_);
    // TODO(crbug.com/646113): Clean this up when DictionaryValue and ListValue
    // are completely inlined.
    case Type::DICTIONARY: {
      if ((*dict_ptr_)->size() != (*other->dict_ptr_)->size())
        return false;

      return std::equal(std::begin(**dict_ptr_), std::end(**dict_ptr_),
                        std::begin(**(other->dict_ptr_)),
                        [](const DictStorage::value_type& lhs,
                           const DictStorage::value_type& rhs) {
                          if (lhs.first != rhs.first)
                            return false;

                          return lhs.second->Equals(rhs.second.get());
                        });
    }
    case Type::LIST: {
      if (list_->size() != other->list_->size())
        return false;

      return std::equal(std::begin(*list_), std::end(*list_),
                        std::begin(*(other->list_)),
                        [](const ListStorage::value_type& lhs,
                           const ListStorage::value_type& rhs) {
                          return lhs->Equals(rhs.get());
                        });
    }
  }

  NOTREACHED();
  return false;
}

// static
bool Value::Equals(const Value* a, const Value* b) {
  if ((a == NULL) && (b == NULL)) return true;
  if ((a == NULL) ^  (b == NULL)) return false;
  return a->Equals(b);
}

void Value::InternalCopyFundamentalValue(const Value& that) {
  switch (type_) {
    case Type::NONE:
      // Nothing to do.
      return;

    case Type::BOOLEAN:
      bool_value_ = that.bool_value_;
      return;
    case Type::INTEGER:
      int_value_ = that.int_value_;
      return;
    case Type::DOUBLE:
      double_value_ = that.double_value_;
      return;

    default:
      NOTREACHED();
  }
}

void Value::InternalCopyConstructFrom(const Value& that) {
  type_ = that.type_;

  switch (type_) {
    case Type::NONE:
    case Type::BOOLEAN:
    case Type::INTEGER:
    case Type::DOUBLE:
      InternalCopyFundamentalValue(that);
      return;

    case Type::STRING:
      string_value_.Init(*that.string_value_);
      return;
    case Type::BINARY:
      binary_value_.Init(*that.binary_value_);
      return;
    // DictStorage and ListStorage are move-only types due to the presence of
    // unique_ptrs. This is why the call to |CreateDeepCopy| is necessary here.
    // TODO(crbug.com/646113): Clean this up when DictStorage and ListStorage
    // can be copied directly.
    case Type::DICTIONARY:
      dict_ptr_.Init(std::move(*that.CreateDeepCopy()->dict_ptr_));
      return;
    case Type::LIST:
      list_.Init(std::move(*that.CreateDeepCopy()->list_));
      return;
  }
}

void Value::InternalMoveConstructFrom(Value&& that) {
  type_ = that.type_;

  switch (type_) {
    case Type::NONE:
    case Type::BOOLEAN:
    case Type::INTEGER:
    case Type::DOUBLE:
      InternalCopyFundamentalValue(that);
      return;

    case Type::STRING:
      string_value_.InitFromMove(std::move(that.string_value_));
      return;
    case Type::BINARY:
      binary_value_.InitFromMove(std::move(that.binary_value_));
      return;
    case Type::DICTIONARY:
      dict_ptr_.InitFromMove(std::move(that.dict_ptr_));
      return;
    case Type::LIST:
      list_.InitFromMove(std::move(that.list_));
      return;
  }
}

void Value::InternalCopyAssignFrom(const Value& that) {
  type_ = that.type_;

  switch (type_) {
    case Type::NONE:
    case Type::BOOLEAN:
    case Type::INTEGER:
    case Type::DOUBLE:
      InternalCopyFundamentalValue(that);
      return;

    case Type::STRING:
      *string_value_ = *that.string_value_;
      return;
    case Type::BINARY:
      *binary_value_ = *that.binary_value_;
      return;
    // DictStorage and ListStorage are move-only types due to the presence of
    // unique_ptrs. This is why the call to |CreateDeepCopy| is necessary here.
    // TODO(crbug.com/646113): Clean this up when DictStorage and ListStorage
    // can be copied directly.
    case Type::DICTIONARY:
      *dict_ptr_ = std::move(*that.CreateDeepCopy()->dict_ptr_);
      return;
    case Type::LIST:
      *list_ = std::move(*that.CreateDeepCopy()->list_);
      return;
  }
}

void Value::InternalMoveAssignFrom(Value&& that) {
  type_ = that.type_;

  switch (type_) {
    case Type::NONE:
    case Type::BOOLEAN:
    case Type::INTEGER:
    case Type::DOUBLE:
      InternalCopyFundamentalValue(that);
      return;

    case Type::STRING:
      *string_value_ = std::move(*that.string_value_);
      return;
    case Type::BINARY:
      *binary_value_ = std::move(*that.binary_value_);
      return;
    case Type::DICTIONARY:
      *dict_ptr_ = std::move(*that.dict_ptr_);
      return;
    case Type::LIST:
      *list_ = std::move(*that.list_);
      return;
  }
}

void Value::InternalCleanup() {
  switch (type_) {
    case Type::NONE:
    case Type::BOOLEAN:
    case Type::INTEGER:
    case Type::DOUBLE:
      // Nothing to do
      return;

    case Type::STRING:
      string_value_.Destroy();
      return;
    case Type::BINARY:
      binary_value_.Destroy();
      return;
    case Type::DICTIONARY:
      dict_ptr_.Destroy();
      return;
    case Type::LIST:
      list_.Destroy();
      return;
  }
}

///////////////////// DictionaryValue ////////////////////

// static
std::unique_ptr<DictionaryValue> DictionaryValue::From(
    std::unique_ptr<Value> value) {
  DictionaryValue* out;
  if (value && value->GetAsDictionary(&out)) {
    ignore_result(value.release());
    return WrapUnique(out);
  }
  return nullptr;
}

DictionaryValue::DictionaryValue() : Value(Type::DICTIONARY) {}

bool DictionaryValue::HasKey(StringPiece key) const {
  DCHECK(IsStringUTF8(key));
  auto current_entry = (*dict_ptr_)->find(key.as_string());
  DCHECK((current_entry == (*dict_ptr_)->end()) || current_entry->second);
  return current_entry != (*dict_ptr_)->end();
}

void DictionaryValue::Clear() {
  (*dict_ptr_)->clear();
}

void DictionaryValue::Set(StringPiece path, std::unique_ptr<Value> in_value) {
  DCHECK(IsStringUTF8(path));
  DCHECK(in_value);

  StringPiece current_path(path);
  DictionaryValue* current_dictionary = this;
  for (size_t delimiter_position = current_path.find('.');
       delimiter_position != StringPiece::npos;
       delimiter_position = current_path.find('.')) {
    // Assume that we're indexing into a dictionary.
    StringPiece key = current_path.substr(0, delimiter_position);
    DictionaryValue* child_dictionary = nullptr;
    if (!current_dictionary->GetDictionary(key, &child_dictionary)) {
      child_dictionary = new DictionaryValue;
      current_dictionary->SetWithoutPathExpansion(
          key, base::WrapUnique(child_dictionary));
    }

    current_dictionary = child_dictionary;
    current_path = current_path.substr(delimiter_position + 1);
  }

  current_dictionary->SetWithoutPathExpansion(current_path,
                                              std::move(in_value));
}

void DictionaryValue::Set(StringPiece path, Value* in_value) {
  Set(path, WrapUnique(in_value));
}

void DictionaryValue::SetBoolean(StringPiece path, bool in_value) {
  Set(path, new Value(in_value));
}

void DictionaryValue::SetInteger(StringPiece path, int in_value) {
  Set(path, new Value(in_value));
}

void DictionaryValue::SetDouble(StringPiece path, double in_value) {
  Set(path, new Value(in_value));
}

void DictionaryValue::SetString(StringPiece path, StringPiece in_value) {
  Set(path, new StringValue(in_value));
}

void DictionaryValue::SetString(StringPiece path, const string16& in_value) {
  Set(path, new StringValue(in_value));
}

void DictionaryValue::SetWithoutPathExpansion(StringPiece key,
                                              std::unique_ptr<Value> in_value) {
  (**dict_ptr_)[key.as_string()] = std::move(in_value);
}

void DictionaryValue::SetWithoutPathExpansion(StringPiece key,
                                              Value* in_value) {
  SetWithoutPathExpansion(key, WrapUnique(in_value));
}

void DictionaryValue::SetBooleanWithoutPathExpansion(StringPiece path,
                                                     bool in_value) {
  SetWithoutPathExpansion(path, base::MakeUnique<base::Value>(in_value));
}

void DictionaryValue::SetIntegerWithoutPathExpansion(StringPiece path,
                                                     int in_value) {
  SetWithoutPathExpansion(path, base::MakeUnique<base::Value>(in_value));
}

void DictionaryValue::SetDoubleWithoutPathExpansion(StringPiece path,
                                                    double in_value) {
  SetWithoutPathExpansion(path, base::MakeUnique<base::Value>(in_value));
}

void DictionaryValue::SetStringWithoutPathExpansion(StringPiece path,
                                                    StringPiece in_value) {
  SetWithoutPathExpansion(path, base::MakeUnique<base::StringValue>(in_value));
}

void DictionaryValue::SetStringWithoutPathExpansion(StringPiece path,
                                                    const string16& in_value) {
  SetWithoutPathExpansion(path, base::MakeUnique<base::StringValue>(in_value));
}

bool DictionaryValue::Get(StringPiece path,
                          const Value** out_value) const {
  DCHECK(IsStringUTF8(path));
  StringPiece current_path(path);
  const DictionaryValue* current_dictionary = this;
  for (size_t delimiter_position = current_path.find('.');
       delimiter_position != std::string::npos;
       delimiter_position = current_path.find('.')) {
    const DictionaryValue* child_dictionary = NULL;
    if (!current_dictionary->GetDictionaryWithoutPathExpansion(
            current_path.substr(0, delimiter_position), &child_dictionary)) {
      return false;
    }

    current_dictionary = child_dictionary;
    current_path = current_path.substr(delimiter_position + 1);
  }

  return current_dictionary->GetWithoutPathExpansion(current_path, out_value);
}

bool DictionaryValue::Get(StringPiece path, Value** out_value)  {
  return static_cast<const DictionaryValue&>(*this).Get(
      path,
      const_cast<const Value**>(out_value));
}

bool DictionaryValue::GetBoolean(StringPiece path, bool* bool_value) const {
  const Value* value;
  if (!Get(path, &value))
    return false;

  return value->GetAsBoolean(bool_value);
}

bool DictionaryValue::GetInteger(StringPiece path, int* out_value) const {
  const Value* value;
  if (!Get(path, &value))
    return false;

  return value->GetAsInteger(out_value);
}

bool DictionaryValue::GetDouble(StringPiece path, double* out_value) const {
  const Value* value;
  if (!Get(path, &value))
    return false;

  return value->GetAsDouble(out_value);
}

bool DictionaryValue::GetString(StringPiece path,
                                std::string* out_value) const {
  const Value* value;
  if (!Get(path, &value))
    return false;

  return value->GetAsString(out_value);
}

bool DictionaryValue::GetString(StringPiece path, string16* out_value) const {
  const Value* value;
  if (!Get(path, &value))
    return false;

  return value->GetAsString(out_value);
}

bool DictionaryValue::GetStringASCII(StringPiece path,
                                     std::string* out_value) const {
  std::string out;
  if (!GetString(path, &out))
    return false;

  if (!IsStringASCII(out)) {
    NOTREACHED();
    return false;
  }

  out_value->assign(out);
  return true;
}

bool DictionaryValue::GetBinary(StringPiece path,
                                const BinaryValue** out_value) const {
  const Value* value;
  bool result = Get(path, &value);
  if (!result || !value->IsType(Type::BINARY))
    return false;

  if (out_value)
    *out_value = value;

  return true;
}

bool DictionaryValue::GetBinary(StringPiece path, BinaryValue** out_value) {
  return static_cast<const DictionaryValue&>(*this).GetBinary(
      path,
      const_cast<const BinaryValue**>(out_value));
}

bool DictionaryValue::GetDictionary(StringPiece path,
                                    const DictionaryValue** out_value) const {
  const Value* value;
  bool result = Get(path, &value);
  if (!result || !value->IsType(Type::DICTIONARY))
    return false;

  if (out_value)
    *out_value = static_cast<const DictionaryValue*>(value);

  return true;
}

bool DictionaryValue::GetDictionary(StringPiece path,
                                    DictionaryValue** out_value) {
  return static_cast<const DictionaryValue&>(*this).GetDictionary(
      path,
      const_cast<const DictionaryValue**>(out_value));
}

bool DictionaryValue::GetList(StringPiece path,
                              const ListValue** out_value) const {
  const Value* value;
  bool result = Get(path, &value);
  if (!result || !value->IsType(Type::LIST))
    return false;

  if (out_value)
    *out_value = static_cast<const ListValue*>(value);

  return true;
}

bool DictionaryValue::GetList(StringPiece path, ListValue** out_value) {
  return static_cast<const DictionaryValue&>(*this).GetList(
      path,
      const_cast<const ListValue**>(out_value));
}

bool DictionaryValue::GetWithoutPathExpansion(StringPiece key,
                                              const Value** out_value) const {
  DCHECK(IsStringUTF8(key));
  auto entry_iterator = (*dict_ptr_)->find(key.as_string());
  if (entry_iterator == (*dict_ptr_)->end())
    return false;

  if (out_value)
    *out_value = entry_iterator->second.get();
  return true;
}

bool DictionaryValue::GetWithoutPathExpansion(StringPiece key,
                                              Value** out_value) {
  return static_cast<const DictionaryValue&>(*this).GetWithoutPathExpansion(
      key,
      const_cast<const Value**>(out_value));
}

bool DictionaryValue::GetBooleanWithoutPathExpansion(StringPiece key,
                                                     bool* out_value) const {
  const Value* value;
  if (!GetWithoutPathExpansion(key, &value))
    return false;

  return value->GetAsBoolean(out_value);
}

bool DictionaryValue::GetIntegerWithoutPathExpansion(StringPiece key,
                                                     int* out_value) const {
  const Value* value;
  if (!GetWithoutPathExpansion(key, &value))
    return false;

  return value->GetAsInteger(out_value);
}

bool DictionaryValue::GetDoubleWithoutPathExpansion(StringPiece key,
                                                    double* out_value) const {
  const Value* value;
  if (!GetWithoutPathExpansion(key, &value))
    return false;

  return value->GetAsDouble(out_value);
}

bool DictionaryValue::GetStringWithoutPathExpansion(
    StringPiece key,
    std::string* out_value) const {
  const Value* value;
  if (!GetWithoutPathExpansion(key, &value))
    return false;

  return value->GetAsString(out_value);
}

bool DictionaryValue::GetStringWithoutPathExpansion(StringPiece key,
                                                    string16* out_value) const {
  const Value* value;
  if (!GetWithoutPathExpansion(key, &value))
    return false;

  return value->GetAsString(out_value);
}

bool DictionaryValue::GetDictionaryWithoutPathExpansion(
    StringPiece key,
    const DictionaryValue** out_value) const {
  const Value* value;
  bool result = GetWithoutPathExpansion(key, &value);
  if (!result || !value->IsType(Type::DICTIONARY))
    return false;

  if (out_value)
    *out_value = static_cast<const DictionaryValue*>(value);

  return true;
}

bool DictionaryValue::GetDictionaryWithoutPathExpansion(
    StringPiece key,
    DictionaryValue** out_value) {
  const DictionaryValue& const_this =
      static_cast<const DictionaryValue&>(*this);
  return const_this.GetDictionaryWithoutPathExpansion(
          key,
          const_cast<const DictionaryValue**>(out_value));
}

bool DictionaryValue::GetListWithoutPathExpansion(
    StringPiece key,
    const ListValue** out_value) const {
  const Value* value;
  bool result = GetWithoutPathExpansion(key, &value);
  if (!result || !value->IsType(Type::LIST))
    return false;

  if (out_value)
    *out_value = static_cast<const ListValue*>(value);

  return true;
}

bool DictionaryValue::GetListWithoutPathExpansion(StringPiece key,
                                                  ListValue** out_value) {
  return
      static_cast<const DictionaryValue&>(*this).GetListWithoutPathExpansion(
          key,
          const_cast<const ListValue**>(out_value));
}

bool DictionaryValue::Remove(StringPiece path,
                             std::unique_ptr<Value>* out_value) {
  DCHECK(IsStringUTF8(path));
  StringPiece current_path(path);
  DictionaryValue* current_dictionary = this;
  size_t delimiter_position = current_path.rfind('.');
  if (delimiter_position != StringPiece::npos) {
    if (!GetDictionary(current_path.substr(0, delimiter_position),
                       &current_dictionary))
      return false;
    current_path = current_path.substr(delimiter_position + 1);
  }

  return current_dictionary->RemoveWithoutPathExpansion(current_path,
                                                        out_value);
}

bool DictionaryValue::RemoveWithoutPathExpansion(
    StringPiece key,
    std::unique_ptr<Value>* out_value) {
  DCHECK(IsStringUTF8(key));
  auto entry_iterator = (*dict_ptr_)->find(key.as_string());
  if (entry_iterator == (*dict_ptr_)->end())
    return false;

  if (out_value)
    *out_value = std::move(entry_iterator->second);
  (*dict_ptr_)->erase(entry_iterator);
  return true;
}

bool DictionaryValue::RemovePath(StringPiece path,
                                 std::unique_ptr<Value>* out_value) {
  bool result = false;
  size_t delimiter_position = path.find('.');

  if (delimiter_position == std::string::npos)
    return RemoveWithoutPathExpansion(path, out_value);

  StringPiece subdict_path = path.substr(0, delimiter_position);
  DictionaryValue* subdict = NULL;
  if (!GetDictionary(subdict_path, &subdict))
    return false;
  result = subdict->RemovePath(path.substr(delimiter_position + 1),
                               out_value);
  if (result && subdict->empty())
    RemoveWithoutPathExpansion(subdict_path, NULL);

  return result;
}

std::unique_ptr<DictionaryValue> DictionaryValue::DeepCopyWithoutEmptyChildren()
    const {
  std::unique_ptr<DictionaryValue> copy =
      CopyDictionaryWithoutEmptyChildren(*this);
  if (!copy)
    copy.reset(new DictionaryValue);
  return copy;
}

void DictionaryValue::MergeDictionary(const DictionaryValue* dictionary) {
  for (DictionaryValue::Iterator it(*dictionary); !it.IsAtEnd(); it.Advance()) {
    const Value* merge_value = &it.value();
    // Check whether we have to merge dictionaries.
    if (merge_value->IsType(Value::Type::DICTIONARY)) {
      DictionaryValue* sub_dict;
      if (GetDictionaryWithoutPathExpansion(it.key(), &sub_dict)) {
        sub_dict->MergeDictionary(
            static_cast<const DictionaryValue*>(merge_value));
        continue;
      }
    }
    // All other cases: Make a copy and hook it up.
    SetWithoutPathExpansion(it.key(),
                            base::WrapUnique(merge_value->DeepCopy()));
  }
}

void DictionaryValue::Swap(DictionaryValue* other) {
  dict_ptr_->swap(*(other->dict_ptr_));
}

DictionaryValue::Iterator::Iterator(const DictionaryValue& target)
    : target_(target), it_((*target.dict_ptr_)->begin()) {}

DictionaryValue::Iterator::Iterator(const Iterator& other) = default;

DictionaryValue::Iterator::~Iterator() {}

DictionaryValue* DictionaryValue::DeepCopy() const {
  return static_cast<DictionaryValue*>(Value::DeepCopy());
}

std::unique_ptr<DictionaryValue> DictionaryValue::CreateDeepCopy() const {
  return WrapUnique(DeepCopy());
}

///////////////////// ListValue ////////////////////

// static
std::unique_ptr<ListValue> ListValue::From(std::unique_ptr<Value> value) {
  ListValue* out;
  if (value && value->GetAsList(&out)) {
    ignore_result(value.release());
    return WrapUnique(out);
  }
  return nullptr;
}

ListValue::ListValue() : Value(Type::LIST) {}

void ListValue::Clear() {
  list_->clear();
}

bool ListValue::Set(size_t index, Value* in_value) {
  return Set(index, WrapUnique(in_value));
}

bool ListValue::Set(size_t index, std::unique_ptr<Value> in_value) {
  if (!in_value)
    return false;

  if (index >= list_->size()) {
    // Pad out any intermediate indexes with null settings
    while (index > list_->size())
      Append(CreateNullValue());
    Append(std::move(in_value));
  } else {
    // TODO(dcheng): remove this DCHECK once the raw pointer version is removed?
    DCHECK((*list_)[index] != in_value);
    (*list_)[index] = std::move(in_value);
  }
  return true;
}

bool ListValue::Get(size_t index, const Value** out_value) const {
  if (index >= list_->size())
    return false;

  if (out_value)
    *out_value = (*list_)[index].get();

  return true;
}

bool ListValue::Get(size_t index, Value** out_value) {
  return static_cast<const ListValue&>(*this).Get(
      index,
      const_cast<const Value**>(out_value));
}

bool ListValue::GetBoolean(size_t index, bool* bool_value) const {
  const Value* value;
  if (!Get(index, &value))
    return false;

  return value->GetAsBoolean(bool_value);
}

bool ListValue::GetInteger(size_t index, int* out_value) const {
  const Value* value;
  if (!Get(index, &value))
    return false;

  return value->GetAsInteger(out_value);
}

bool ListValue::GetDouble(size_t index, double* out_value) const {
  const Value* value;
  if (!Get(index, &value))
    return false;

  return value->GetAsDouble(out_value);
}

bool ListValue::GetString(size_t index, std::string* out_value) const {
  const Value* value;
  if (!Get(index, &value))
    return false;

  return value->GetAsString(out_value);
}

bool ListValue::GetString(size_t index, string16* out_value) const {
  const Value* value;
  if (!Get(index, &value))
    return false;

  return value->GetAsString(out_value);
}

bool ListValue::GetBinary(size_t index, const BinaryValue** out_value) const {
  const Value* value;
  bool result = Get(index, &value);
  if (!result || !value->IsType(Type::BINARY))
    return false;

  if (out_value)
    *out_value = value;

  return true;
}

bool ListValue::GetBinary(size_t index, BinaryValue** out_value) {
  return static_cast<const ListValue&>(*this).GetBinary(
      index,
      const_cast<const BinaryValue**>(out_value));
}

bool ListValue::GetDictionary(size_t index,
                              const DictionaryValue** out_value) const {
  const Value* value;
  bool result = Get(index, &value);
  if (!result || !value->IsType(Type::DICTIONARY))
    return false;

  if (out_value)
    *out_value = static_cast<const DictionaryValue*>(value);

  return true;
}

bool ListValue::GetDictionary(size_t index, DictionaryValue** out_value) {
  return static_cast<const ListValue&>(*this).GetDictionary(
      index,
      const_cast<const DictionaryValue**>(out_value));
}

bool ListValue::GetList(size_t index, const ListValue** out_value) const {
  const Value* value;
  bool result = Get(index, &value);
  if (!result || !value->IsType(Type::LIST))
    return false;

  if (out_value)
    *out_value = static_cast<const ListValue*>(value);

  return true;
}

bool ListValue::GetList(size_t index, ListValue** out_value) {
  return static_cast<const ListValue&>(*this).GetList(
      index,
      const_cast<const ListValue**>(out_value));
}

bool ListValue::Remove(size_t index, std::unique_ptr<Value>* out_value) {
  if (index >= list_->size())
    return false;

  if (out_value)
    *out_value = std::move((*list_)[index]);

  list_->erase(list_->begin() + index);
  return true;
}

bool ListValue::Remove(const Value& value, size_t* index) {
  for (auto it = list_->begin(); it != list_->end(); ++it) {
    if ((*it)->Equals(&value)) {
      size_t previous_index = it - list_->begin();
      list_->erase(it);

      if (index)
        *index = previous_index;
      return true;
    }
  }
  return false;
}

ListValue::iterator ListValue::Erase(iterator iter,
                                     std::unique_ptr<Value>* out_value) {
  if (out_value)
    *out_value = std::move(*ListStorage::iterator(iter));

  return list_->erase(iter);
}

void ListValue::Append(std::unique_ptr<Value> in_value) {
  list_->push_back(std::move(in_value));
}

#if !defined(OS_LINUX)
void ListValue::Append(Value* in_value) {
  DCHECK(in_value);
  Append(WrapUnique(in_value));
}
#endif

void ListValue::AppendBoolean(bool in_value) {
  Append(MakeUnique<Value>(in_value));
}

void ListValue::AppendInteger(int in_value) {
  Append(MakeUnique<Value>(in_value));
}

void ListValue::AppendDouble(double in_value) {
  Append(MakeUnique<Value>(in_value));
}

void ListValue::AppendString(StringPiece in_value) {
  Append(MakeUnique<StringValue>(in_value));
}

void ListValue::AppendString(const string16& in_value) {
  Append(MakeUnique<StringValue>(in_value));
}

void ListValue::AppendStrings(const std::vector<std::string>& in_values) {
  for (std::vector<std::string>::const_iterator it = in_values.begin();
       it != in_values.end(); ++it) {
    AppendString(*it);
  }
}

void ListValue::AppendStrings(const std::vector<string16>& in_values) {
  for (std::vector<string16>::const_iterator it = in_values.begin();
       it != in_values.end(); ++it) {
    AppendString(*it);
  }
}

bool ListValue::AppendIfNotPresent(std::unique_ptr<Value> in_value) {
  DCHECK(in_value);
  for (const auto& entry : *list_) {
    if (entry->Equals(in_value.get())) {
      return false;
    }
  }
  list_->push_back(std::move(in_value));
  return true;
}

bool ListValue::Insert(size_t index, std::unique_ptr<Value> in_value) {
  DCHECK(in_value);
  if (index > list_->size())
    return false;

  list_->insert(list_->begin() + index, std::move(in_value));
  return true;
}

ListValue::const_iterator ListValue::Find(const Value& value) const {
  return std::find_if(list_->begin(), list_->end(),
                      [&value](const std::unique_ptr<Value>& entry) {
                        return entry->Equals(&value);
                      });
}

void ListValue::Swap(ListValue* other) {
  list_->swap(*(other->list_));
}

ListValue* ListValue::DeepCopy() const {
  return static_cast<ListValue*>(Value::DeepCopy());
}

std::unique_ptr<ListValue> ListValue::CreateDeepCopy() const {
  return WrapUnique(DeepCopy());
}

ValueSerializer::~ValueSerializer() {
}

ValueDeserializer::~ValueDeserializer() {
}

std::ostream& operator<<(std::ostream& out, const Value& value) {
  std::string json;
  JSONWriter::WriteWithOptions(value, JSONWriter::OPTIONS_PRETTY_PRINT, &json);
  return out << json;
}

std::ostream& operator<<(std::ostream& out, const Value::Type& type) {
  if (static_cast<int>(type) < 0 ||
      static_cast<size_t>(type) >= arraysize(kTypeNames))
    return out << "Invalid Type (index = " << static_cast<int>(type) << ")";
  return out << Value::GetTypeName(type);
}

}  // namespace base

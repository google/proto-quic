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
std::unique_ptr<Value> CopyListWithoutEmptyChildren(const Value& list) {
  Value copy(Value::Type::LIST);
  for (const auto& entry : list.GetList()) {
    std::unique_ptr<Value> child_copy = CopyWithoutEmptyChildren(entry);
    if (child_copy)
      copy.GetList().push_back(std::move(*child_copy));
  }
  return copy.GetList().empty() ? nullptr : MakeUnique<Value>(std::move(copy));
}

std::unique_ptr<DictionaryValue> CopyDictionaryWithoutEmptyChildren(
    const DictionaryValue& dict) {
  std::unique_ptr<DictionaryValue> copy;
  for (DictionaryValue::Iterator it(dict); !it.IsAtEnd(); it.Advance()) {
    std::unique_ptr<Value> child_copy = CopyWithoutEmptyChildren(it.value());
    if (child_copy) {
      if (!copy)
        copy = MakeUnique<DictionaryValue>();
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
      return MakeUnique<Value>(node);
  }
}

}  // namespace

// static
std::unique_ptr<Value> Value::CreateWithCopiedBuffer(const char* buffer,
                                                     size_t size) {
  return MakeUnique<Value>(BlobStorage(buffer, buffer + size));
}

Value::Value(const Value& that) {
  InternalCopyConstructFrom(that);
}

Value::Value(Value&& that) noexcept {
  InternalMoveConstructFrom(std::move(that));
}

Value::Value() noexcept : type_(Type::NONE) {}

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
      dict_.Init();
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

Value::Value(std::string&& in_string) noexcept : type_(Type::STRING) {
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

Value::Value(const BlobStorage& in_blob) : type_(Type::BINARY) {
  binary_value_.Init(in_blob);
}

Value::Value(BlobStorage&& in_blob) noexcept : type_(Type::BINARY) {
  binary_value_.Init(std::move(in_blob));
}

Value::Value(DictStorage&& in_dict) noexcept : type_(Type::DICTIONARY) {
  dict_.Init(std::move(in_dict));
}

Value::Value(const ListStorage& in_list) : type_(Type::LIST) {
  list_.Init(in_list);
}

Value::Value(ListStorage&& in_list) noexcept : type_(Type::LIST) {
  list_.Init(std::move(in_list));
}

Value& Value::operator=(const Value& that) {
  if (type_ == that.type_) {
    InternalCopyAssignFromSameType(that);
  } else {
    // This is not a self assignment because the type_ doesn't match.
    InternalCleanup();
    InternalCopyConstructFrom(that);
  }

  return *this;
}

Value& Value::operator=(Value&& that) noexcept {
  InternalCleanup();
  InternalMoveConstructFrom(std::move(that));

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

const Value::BlobStorage& Value::GetBlob() const {
  CHECK(is_blob());
  return *binary_value_;
}

Value::ListStorage& Value::GetList() {
  CHECK(is_list());
  return *list_;
}

const Value::ListStorage& Value::GetList() const {
  CHECK(is_list());
  return *list_;
}

Value::dict_iterator Value::FindKey(const char* key) {
  return FindKey(std::string(key));
}

Value::dict_iterator Value::FindKey(const std::string& key) {
  CHECK(is_dict());
  return dict_iterator(dict_->find(key));
}

Value::const_dict_iterator Value::FindKey(const char* key) const {
  return FindKey(std::string(key));
}

Value::const_dict_iterator Value::FindKey(const std::string& key) const {
  CHECK(is_dict());
  return const_dict_iterator(dict_->find(key));
}

Value::dict_iterator Value::FindKeyOfType(const char* key, Type type) {
  return FindKeyOfType(std::string(key), type);
}

Value::dict_iterator Value::FindKeyOfType(const std::string& key, Type type) {
  CHECK(is_dict());
  auto iter = dict_->find(key);
  return dict_iterator((iter != dict_->end() && iter->second->IsType(type))
                           ? iter
                           : dict_->end());
}

Value::const_dict_iterator Value::FindKeyOfType(const char* key,
                                                Type type) const {
  return FindKeyOfType(std::string(key), type);
}

Value::const_dict_iterator Value::FindKeyOfType(const std::string& key,
                                                Type type) const {
  CHECK(is_dict());
  auto iter = dict_->find(key);
  return const_dict_iterator(
      (iter != dict_->end() && iter->second->IsType(type)) ? iter
                                                           : dict_->end());
}

Value::dict_iterator Value::SetKey(const char* key, Value value) {
  return SetKey(std::string(key), std::move(value));
}

Value::dict_iterator Value::SetKey(const std::string& key, Value value) {
  CHECK(is_dict());
  auto iter = dict_->find(key);
  if (iter != dict_->end()) {
    *iter->second = std::move(value);
    return dict_iterator(iter);
  }

  return dict_iterator(
      dict_->emplace(key, MakeUnique<Value>(std::move(value))).first);
}

Value::dict_iterator Value::SetKey(std::string&& key, Value value) {
  CHECK(is_dict());
  auto iter = dict_->find(key);
  if (iter != dict_->end()) {
    *iter->second = std::move(value);
    return dict_iterator(iter);
  }

  return dict_iterator(
      dict_->emplace(std::move(key), MakeUnique<Value>(std::move(value)))
          .first);
}

Value::dict_iterator Value::DictEnd() {
  CHECK(is_dict());
  return dict_iterator(dict_->end());
}

Value::const_dict_iterator Value::DictEnd() const {
  CHECK(is_dict());
  return const_dict_iterator(dict_->end());
}

Value::dict_iterator_proxy Value::DictItems() {
  CHECK(is_dict());
  return dict_iterator_proxy(&*dict_);
}

Value::const_dict_iterator_proxy Value::DictItems() const {
  CHECK(is_dict());
  return const_dict_iterator_proxy(&*dict_);
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

bool Value::GetAsString(const Value** out_value) const {
  if (out_value && is_string()) {
    *out_value = static_cast<const Value*>(this);
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
  return new Value(*this);
}

std::unique_ptr<Value> Value::CreateDeepCopy() const {
  return MakeUnique<Value>(*this);
}

bool operator==(const Value& lhs, const Value& rhs) {
  if (lhs.type_ != rhs.type_)
    return false;

  switch (lhs.type_) {
    case Value::Type::NONE:
      return true;
    case Value::Type::BOOLEAN:
      return lhs.bool_value_ == rhs.bool_value_;
    case Value::Type::INTEGER:
      return lhs.int_value_ == rhs.int_value_;
    case Value::Type::DOUBLE:
      return lhs.double_value_ == rhs.double_value_;
    case Value::Type::STRING:
      return *lhs.string_value_ == *rhs.string_value_;
    case Value::Type::BINARY:
      return *lhs.binary_value_ == *rhs.binary_value_;
    // TODO(crbug.com/646113): Clean this up when DictionaryValue and ListValue
    // are completely inlined.
    case Value::Type::DICTIONARY:
      if (lhs.dict_->size() != rhs.dict_->size())
        return false;
      return std::equal(std::begin(*lhs.dict_), std::end(*lhs.dict_),
                        std::begin(*rhs.dict_),
                        [](const Value::DictStorage::value_type& u,
                           const Value::DictStorage::value_type& v) {
                          return std::tie(u.first, *u.second) ==
                                 std::tie(v.first, *v.second);
                        });
    case Value::Type::LIST:
      return *lhs.list_ == *rhs.list_;
  }

  NOTREACHED();
  return false;
}

bool operator!=(const Value& lhs, const Value& rhs) {
  return !(lhs == rhs);
}

bool operator<(const Value& lhs, const Value& rhs) {
  if (lhs.type_ != rhs.type_)
    return lhs.type_ < rhs.type_;

  switch (lhs.type_) {
    case Value::Type::NONE:
      return false;
    case Value::Type::BOOLEAN:
      return lhs.bool_value_ < rhs.bool_value_;
    case Value::Type::INTEGER:
      return lhs.int_value_ < rhs.int_value_;
    case Value::Type::DOUBLE:
      return lhs.double_value_ < rhs.double_value_;
    case Value::Type::STRING:
      return *lhs.string_value_ < *rhs.string_value_;
    case Value::Type::BINARY:
      return *lhs.binary_value_ < *rhs.binary_value_;
    // TODO(crbug.com/646113): Clean this up when DictionaryValue and ListValue
    // are completely inlined.
    case Value::Type::DICTIONARY:
      return std::lexicographical_compare(
          std::begin(*lhs.dict_), std::end(*lhs.dict_), std::begin(*rhs.dict_),
          std::end(*rhs.dict_),
          [](const Value::DictStorage::value_type& u,
             const Value::DictStorage::value_type& v) {
            return std::tie(u.first, *u.second) < std::tie(v.first, *v.second);
          });
    case Value::Type::LIST:
      return *lhs.list_ < *rhs.list_;
  }

  NOTREACHED();
  return false;
}

bool operator>(const Value& lhs, const Value& rhs) {
  return rhs < lhs;
}

bool operator<=(const Value& lhs, const Value& rhs) {
  return !(rhs < lhs);
}

bool operator>=(const Value& lhs, const Value& rhs) {
  return !(lhs < rhs);
}

bool Value::Equals(const Value* other) const {
  DCHECK(other);
  return *this == *other;
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
    // DictStorage is a move-only type due to the presence of unique_ptrs. This
    // is why the explicit copy of every element is necessary here.
    // TODO(crbug.com/646113): Clean this up when DictStorage can be copied
    // directly.
    case Type::DICTIONARY:
      dict_.Init();
      for (const auto& it : *that.dict_) {
        dict_->emplace_hint(dict_->end(), it.first,
                            MakeUnique<Value>(*it.second));
      }
      return;
    case Type::LIST:
      list_.Init(*that.list_);
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
      dict_.InitFromMove(std::move(that.dict_));
      return;
    case Type::LIST:
      list_.InitFromMove(std::move(that.list_));
      return;
  }
}

void Value::InternalCopyAssignFromSameType(const Value& that) {
  // TODO(crbug.com/646113): make this a DCHECK once base::Value does not have
  // subclasses.
  CHECK_EQ(type_, that.type_);

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
    // DictStorage is a move-only type due to the presence of unique_ptrs. This
    // is why the explicit call to the copy constructor is necessary here.
    // TODO(crbug.com/646113): Clean this up when DictStorage can be copied
    // directly.
    case Type::DICTIONARY: {
      Value copy = that;
      *dict_ = std::move(*copy.dict_);
      return;
    }
    case Type::LIST:
      *list_ = *that.list_;
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
      dict_.Destroy();
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
  auto current_entry = dict_->find(key.as_string());
  DCHECK((current_entry == dict_->end()) || current_entry->second);
  return current_entry != dict_->end();
}

void DictionaryValue::Clear() {
  dict_->clear();
}

Value* DictionaryValue::Set(StringPiece path, std::unique_ptr<Value> in_value) {
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
      child_dictionary = current_dictionary->SetDictionaryWithoutPathExpansion(
          key, MakeUnique<DictionaryValue>());
    }

    current_dictionary = child_dictionary;
    current_path = current_path.substr(delimiter_position + 1);
  }

  return current_dictionary->SetWithoutPathExpansion(current_path,
                                                     std::move(in_value));
}

Value* DictionaryValue::SetBoolean(StringPiece path, bool in_value) {
  return Set(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetInteger(StringPiece path, int in_value) {
  return Set(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetDouble(StringPiece path, double in_value) {
  return Set(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetString(StringPiece path, StringPiece in_value) {
  return Set(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetString(StringPiece path, const string16& in_value) {
  return Set(path, MakeUnique<Value>(in_value));
}

DictionaryValue* DictionaryValue::SetDictionary(
    StringPiece path,
    std::unique_ptr<DictionaryValue> in_value) {
  return static_cast<DictionaryValue*>(Set(path, std::move(in_value)));
}

ListValue* DictionaryValue::SetList(StringPiece path,
                                    std::unique_ptr<ListValue> in_value) {
  return static_cast<ListValue*>(Set(path, std::move(in_value)));
}

Value* DictionaryValue::SetWithoutPathExpansion(
    StringPiece key,
    std::unique_ptr<Value> in_value) {
  return ((*dict_)[key.as_string()] = std::move(in_value)).get();
}

Value* DictionaryValue::SetBooleanWithoutPathExpansion(StringPiece path,
                                                       bool in_value) {
  return SetWithoutPathExpansion(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetIntegerWithoutPathExpansion(StringPiece path,
                                                       int in_value) {
  return SetWithoutPathExpansion(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetDoubleWithoutPathExpansion(StringPiece path,
                                                      double in_value) {
  return SetWithoutPathExpansion(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetStringWithoutPathExpansion(StringPiece path,
                                                      StringPiece in_value) {
  return SetWithoutPathExpansion(path, MakeUnique<Value>(in_value));
}

Value* DictionaryValue::SetStringWithoutPathExpansion(
    StringPiece path,
    const string16& in_value) {
  return SetWithoutPathExpansion(path, MakeUnique<Value>(in_value));
}

DictionaryValue* DictionaryValue::SetDictionaryWithoutPathExpansion(
    StringPiece path,
    std::unique_ptr<DictionaryValue> in_value) {
  return static_cast<DictionaryValue*>(
      SetWithoutPathExpansion(path, std::move(in_value)));
}

ListValue* DictionaryValue::SetListWithoutPathExpansion(
    StringPiece path,
    std::unique_ptr<ListValue> in_value) {
  return static_cast<ListValue*>(
      SetWithoutPathExpansion(path, std::move(in_value)));
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
                                const Value** out_value) const {
  const Value* value;
  bool result = Get(path, &value);
  if (!result || !value->IsType(Type::BINARY))
    return false;

  if (out_value)
    *out_value = value;

  return true;
}

bool DictionaryValue::GetBinary(StringPiece path, Value** out_value) {
  return static_cast<const DictionaryValue&>(*this).GetBinary(
      path, const_cast<const Value**>(out_value));
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
  auto entry_iterator = dict_->find(key.as_string());
  if (entry_iterator == dict_->end())
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
  auto entry_iterator = dict_->find(key.as_string());
  if (entry_iterator == dict_->end())
    return false;

  if (out_value)
    *out_value = std::move(entry_iterator->second);
  dict_->erase(entry_iterator);
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
    copy = MakeUnique<DictionaryValue>();
  return copy;
}

void DictionaryValue::MergeDictionary(const DictionaryValue* dictionary) {
  CHECK(dictionary->is_dict());
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
    SetWithoutPathExpansion(it.key(), MakeUnique<Value>(*merge_value));
  }
}

void DictionaryValue::Swap(DictionaryValue* other) {
  CHECK(other->is_dict());
  dict_->swap(*other->dict_);
}

DictionaryValue::Iterator::Iterator(const DictionaryValue& target)
    : target_(target), it_(target.dict_->begin()) {}

DictionaryValue::Iterator::Iterator(const Iterator& other) = default;

DictionaryValue::Iterator::~Iterator() {}

DictionaryValue* DictionaryValue::DeepCopy() const {
  return new DictionaryValue(*this);
}

std::unique_ptr<DictionaryValue> DictionaryValue::CreateDeepCopy() const {
  return MakeUnique<DictionaryValue>(*this);
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

ListValue::ListValue(const ListStorage& in_list) : Value(in_list) {}

ListValue::ListValue(ListStorage&& in_list) noexcept
    : Value(std::move(in_list)) {}

void ListValue::Clear() {
  list_->clear();
}

void ListValue::Reserve(size_t n) {
  list_->reserve(n);
}

bool ListValue::Set(size_t index, std::unique_ptr<Value> in_value) {
  if (!in_value)
    return false;

  if (index >= list_->size())
    list_->resize(index + 1);

  (*list_)[index] = std::move(*in_value);
  return true;
}

bool ListValue::Get(size_t index, const Value** out_value) const {
  if (index >= list_->size())
    return false;

  if (out_value)
    *out_value = &(*list_)[index];

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

bool ListValue::GetBinary(size_t index, const Value** out_value) const {
  const Value* value;
  bool result = Get(index, &value);
  if (!result || !value->IsType(Type::BINARY))
    return false;

  if (out_value)
    *out_value = value;

  return true;
}

bool ListValue::GetBinary(size_t index, Value** out_value) {
  return static_cast<const ListValue&>(*this).GetBinary(
      index, const_cast<const Value**>(out_value));
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
    *out_value = MakeUnique<Value>(std::move((*list_)[index]));

  list_->erase(list_->begin() + index);
  return true;
}

bool ListValue::Remove(const Value& value, size_t* index) {
  auto it = std::find(list_->begin(), list_->end(), value);

  if (it == list_->end())
    return false;

  if (index)
    *index = std::distance(list_->begin(), it);

  list_->erase(it);
  return true;
}

ListValue::iterator ListValue::Erase(iterator iter,
                                     std::unique_ptr<Value>* out_value) {
  if (out_value)
    *out_value = MakeUnique<Value>(std::move(*iter));

  return list_->erase(iter);
}

void ListValue::Append(std::unique_ptr<Value> in_value) {
  list_->push_back(std::move(*in_value));
}

void ListValue::AppendBoolean(bool in_value) {
  list_->emplace_back(in_value);
}

void ListValue::AppendInteger(int in_value) {
  list_->emplace_back(in_value);
}

void ListValue::AppendDouble(double in_value) {
  list_->emplace_back(in_value);
}

void ListValue::AppendString(StringPiece in_value) {
  list_->emplace_back(in_value);
}

void ListValue::AppendString(const string16& in_value) {
  list_->emplace_back(in_value);
}

void ListValue::AppendStrings(const std::vector<std::string>& in_values) {
  list_->reserve(list_->size() + in_values.size());
  for (const auto& in_value : in_values)
    list_->emplace_back(in_value);
}

void ListValue::AppendStrings(const std::vector<string16>& in_values) {
  list_->reserve(list_->size() + in_values.size());
  for (const auto& in_value : in_values)
    list_->emplace_back(in_value);
}

bool ListValue::AppendIfNotPresent(std::unique_ptr<Value> in_value) {
  DCHECK(in_value);
  if (std::find(list_->begin(), list_->end(), *in_value) != list_->end())
    return false;

  list_->push_back(std::move(*in_value));
  return true;
}

bool ListValue::Insert(size_t index, std::unique_ptr<Value> in_value) {
  DCHECK(in_value);
  if (index > list_->size())
    return false;

  list_->insert(list_->begin() + index, std::move(*in_value));
  return true;
}

ListValue::const_iterator ListValue::Find(const Value& value) const {
  return std::find(list_->begin(), list_->end(), value);
}

void ListValue::Swap(ListValue* other) {
  CHECK(other->is_list());
  list_->swap(*(other->list_));
}

ListValue* ListValue::DeepCopy() const {
  return new ListValue(*this);
}

std::unique_ptr<ListValue> ListValue::CreateDeepCopy() const {
  return MakeUnique<ListValue>(*this);
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

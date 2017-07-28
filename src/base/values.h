// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file specifies a recursive data storage class called Value intended for
// storing settings and other persistable data.
//
// A Value represents something that can be stored in JSON or passed to/from
// JavaScript. As such, it is NOT a generalized variant type, since only the
// types supported by JavaScript/JSON are supported.
//
// IN PARTICULAR this means that there is no support for int64_t or unsigned
// numbers. Writing JSON with such types would violate the spec. If you need
// something like this, either use a double or make a string value containing
// the number you want.

#ifndef BASE_VALUES_H_
#define BASE_VALUES_H_

#include <stddef.h>
#include <stdint.h>

#include <iosfwd>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/base_export.h"
#include "base/compiler_specific.h"
#include "base/containers/flat_map.h"
#include "base/macros.h"
#include "base/memory/manual_constructor.h"
#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "base/value_iterators.h"

namespace base {

class DictionaryValue;
class ListValue;
class Value;

// The Value class is the base class for Values. A Value can be instantiated
// via the Create*Value() factory methods, or by directly creating instances of
// the subclasses.
//
// See the file-level comment above for more information.
class BASE_EXPORT Value {
 public:
  using BlobStorage = std::vector<char>;
  using DictStorage = base::flat_map<std::string, std::unique_ptr<Value>>;
  using ListStorage = std::vector<Value>;

  enum class Type {
    NONE = 0,
    BOOLEAN,
    INTEGER,
    DOUBLE,
    STRING,
    BINARY,
    DICTIONARY,
    LIST
    // Note: Do not add more types. See the file-level comment above for why.
  };

  // For situations where you want to keep ownership of your buffer, this
  // factory method creates a new BinaryValue by copying the contents of the
  // buffer that's passed in.
  // DEPRECATED, use MakeUnique<Value>(const BlobStorage&) instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  static std::unique_ptr<Value> CreateWithCopiedBuffer(const char* buffer,
                                                       size_t size);

  Value(const Value& that);
  Value(Value&& that) noexcept;
  Value() noexcept;  // A null value.
  explicit Value(Type type);
  explicit Value(bool in_bool);
  explicit Value(int in_int);
  explicit Value(double in_double);

  // Value(const char*) and Value(const char16*) are required despite
  // Value(const std::string&) and Value(const string16&) because otherwise the
  // compiler will choose the Value(bool) constructor for these arguments.
  // Value(std::string&&) allow for efficient move construction.
  // Value(StringPiece) exists due to many callsites passing StringPieces as
  // arguments.
  explicit Value(const char* in_string);
  explicit Value(const std::string& in_string);
  explicit Value(std::string&& in_string) noexcept;
  explicit Value(const char16* in_string);
  explicit Value(const string16& in_string);
  explicit Value(StringPiece in_string);

  explicit Value(const BlobStorage& in_blob);
  explicit Value(BlobStorage&& in_blob) noexcept;

  explicit Value(DictStorage&& in_dict) noexcept;

  explicit Value(const ListStorage& in_list);
  explicit Value(ListStorage&& in_list) noexcept;

  Value& operator=(const Value& that);
  Value& operator=(Value&& that) noexcept;

  ~Value();

  // Returns the name for a given |type|.
  static const char* GetTypeName(Type type);

  // Returns the type of the value stored by the current Value object.
  // Each type will be implemented by only one subclass of Value, so it's
  // safe to use the Type to determine whether you can cast from
  // Value* to (Implementing Class)*.  Also, a Value object never changes
  // its type after construction.
  Type GetType() const { return type_; }  // DEPRECATED, use type().
  Type type() const { return type_; }

  // Returns true if the current object represents a given type.
  bool IsType(Type type) const { return type == type_; }
  bool is_bool() const { return type() == Type::BOOLEAN; }
  bool is_int() const { return type() == Type::INTEGER; }
  bool is_double() const { return type() == Type::DOUBLE; }
  bool is_string() const { return type() == Type::STRING; }
  bool is_blob() const { return type() == Type::BINARY; }
  bool is_dict() const { return type() == Type::DICTIONARY; }
  bool is_list() const { return type() == Type::LIST; }

  // These will all fatally assert if the type doesn't match.
  bool GetBool() const;
  int GetInt() const;
  double GetDouble() const;  // Implicitly converts from int if necessary.
  const std::string& GetString() const;
  const BlobStorage& GetBlob() const;

  ListStorage& GetList();
  const ListStorage& GetList() const;

  using dict_iterator = detail::dict_iterator;
  using const_dict_iterator = detail::const_dict_iterator;
  using dict_iterator_proxy = detail::dict_iterator_proxy;
  using const_dict_iterator_proxy = detail::const_dict_iterator_proxy;

  // TODO(crbug.com/646113): Replace the following const char* and const
  // std::string& overloads with a single base::StringPiece overload when
  // base::less becomes available.

  // |FindKey| looks up |key| in the underlying dictionary. If found, it returns
  // an iterator to the element. Otherwise the end iterator of the dictionary is
  // returned. Callers are expected to compare the returned iterator against
  // |DictEnd()| in order to determine whether |key| was present.
  // Note: This fatally asserts if type() is not Type::DICTIONARY.
  dict_iterator FindKey(const char* key);
  dict_iterator FindKey(const std::string& key);
  const_dict_iterator FindKey(const char* key) const;
  const_dict_iterator FindKey(const std::string& key) const;

  // |FindKeyOfType| is similar to |FindKey|, but it also requires the found
  // value to have type |type|. If no type is found, or the found value is of a
  // different type the end iterator of the dictionary is returned.
  // Callers are expected to compare the returned iterator against |DictEnd()|
  // in order to determine whether |key| was present and of the correct |type|.
  // Note: This fatally asserts if type() is not Type::DICTIONARY.
  dict_iterator FindKeyOfType(const char* key, Type type);
  dict_iterator FindKeyOfType(const std::string& key, Type type);
  const_dict_iterator FindKeyOfType(const char* key, Type type) const;
  const_dict_iterator FindKeyOfType(const std::string& key, Type type) const;

  // |SetKey| looks up |key| in the underlying dictionary and sets the mapped
  // value to |value|. If |key| could not be found, a new element is inserted.
  // An iterator to the modifed item is returned.
  // Note: This fatally asserts if type() is not Type::DICTIONARY.
  dict_iterator SetKey(const char* key, Value value);
  dict_iterator SetKey(const std::string& key, Value value);
  dict_iterator SetKey(std::string&& key, Value value);

  // |DictEnd| returns the end iterator of the underlying dictionary. It is
  // intended to be used with |FindKey| in order to determine whether a given
  // key is present in the dictionary.
  // Note: This fatally asserts if type() is not Type::DICTIONARY.
  dict_iterator DictEnd();
  const_dict_iterator DictEnd() const;

  // |DictItems| returns a proxy object that exposes iterators to the underlying
  // dictionary. These are intended for iteration over all items in the
  // dictionary and are compatible with for-each loops and standard library
  // algorithms.
  // Note: This fatally asserts if type() is not Type::DICTIONARY.
  dict_iterator_proxy DictItems();
  const_dict_iterator_proxy DictItems() const;

  // These methods allow the convenient retrieval of the contents of the Value.
  // If the current object can be converted into the given type, the value is
  // returned through the |out_value| parameter and true is returned;
  // otherwise, false is returned and |out_value| is unchanged.
  // DEPRECATED, use GetBool() instead.
  bool GetAsBoolean(bool* out_value) const;
  // DEPRECATED, use GetInt() instead.
  bool GetAsInteger(int* out_value) const;
  // DEPRECATED, use GetDouble() instead.
  bool GetAsDouble(double* out_value) const;
  // DEPRECATED, use GetString() instead.
  bool GetAsString(std::string* out_value) const;
  bool GetAsString(string16* out_value) const;
  bool GetAsString(const Value** out_value) const;
  bool GetAsString(StringPiece* out_value) const;
  // ListValue::From is the equivalent for std::unique_ptr conversions.
  // DEPRECATED, use GetList() instead.
  bool GetAsList(ListValue** out_value);
  bool GetAsList(const ListValue** out_value) const;
  // DictionaryValue::From is the equivalent for std::unique_ptr conversions.
  bool GetAsDictionary(DictionaryValue** out_value);
  bool GetAsDictionary(const DictionaryValue** out_value) const;
  // Note: Do not add more types. See the file-level comment above for why.

  // This creates a deep copy of the entire Value tree, and returns a pointer
  // to the copy. The caller gets ownership of the copy, of course.
  // Subclasses return their own type directly in their overrides;
  // this works because C++ supports covariant return types.
  // DEPRECATED, use Value's copy constructor instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  Value* DeepCopy() const;
  // DEPRECATED, use Value's copy constructor instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  std::unique_ptr<Value> CreateDeepCopy() const;

  // Comparison operators so that Values can easily be used with standard
  // library algorithms and associative containers.
  BASE_EXPORT friend bool operator==(const Value& lhs, const Value& rhs);
  BASE_EXPORT friend bool operator!=(const Value& lhs, const Value& rhs);
  BASE_EXPORT friend bool operator<(const Value& lhs, const Value& rhs);
  BASE_EXPORT friend bool operator>(const Value& lhs, const Value& rhs);
  BASE_EXPORT friend bool operator<=(const Value& lhs, const Value& rhs);
  BASE_EXPORT friend bool operator>=(const Value& lhs, const Value& rhs);

  // Compares if two Value objects have equal contents.
  // DEPRECATED, use operator==(const Value& lhs, const Value& rhs) instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  bool Equals(const Value* other) const;

 protected:
  // TODO(crbug.com/646113): Make these private once DictionaryValue and
  // ListValue are properly inlined.
  Type type_;

  union {
    bool bool_value_;
    int int_value_;
    double double_value_;
    ManualConstructor<std::string> string_value_;
    ManualConstructor<BlobStorage> binary_value_;
    ManualConstructor<DictStorage> dict_;
    ManualConstructor<ListStorage> list_;
  };

 private:
  void InternalCopyFundamentalValue(const Value& that);
  void InternalCopyConstructFrom(const Value& that);
  void InternalMoveConstructFrom(Value&& that);
  void InternalCopyAssignFromSameType(const Value& that);
  void InternalCleanup();
};

// DictionaryValue provides a key-value dictionary with (optional) "path"
// parsing for recursive access; see the comment at the top of the file. Keys
// are |std::string|s and should be UTF-8 encoded.
class BASE_EXPORT DictionaryValue : public Value {
 public:
  using const_iterator = DictStorage::const_iterator;
  using iterator = DictStorage::iterator;

  // Returns |value| if it is a dictionary, nullptr otherwise.
  static std::unique_ptr<DictionaryValue> From(std::unique_ptr<Value> value);

  DictionaryValue();

  // Returns true if the current dictionary has a value for the given key.
  bool HasKey(StringPiece key) const;

  // Returns the number of Values in this dictionary.
  size_t size() const { return dict_->size(); }

  // Returns whether the dictionary is empty.
  bool empty() const { return dict_->empty(); }

  // Clears any current contents of this dictionary.
  void Clear();

  // Sets the Value associated with the given path starting from this object.
  // A path has the form "<key>" or "<key>.<key>.[...]", where "." indexes
  // into the next DictionaryValue down.  Obviously, "." can't be used
  // within a key, but there are no other restrictions on keys.
  // If the key at any step of the way doesn't exist, or exists but isn't
  // a DictionaryValue, a new DictionaryValue will be created and attached
  // to the path in that location. |in_value| must be non-null.
  // Returns a pointer to the inserted value.
  Value* Set(StringPiece path, std::unique_ptr<Value> in_value);

  // Convenience forms of Set().  These methods will replace any existing
  // value at that path, even if it has a different type.
  Value* SetBoolean(StringPiece path, bool in_value);
  Value* SetInteger(StringPiece path, int in_value);
  Value* SetDouble(StringPiece path, double in_value);
  Value* SetString(StringPiece path, StringPiece in_value);
  Value* SetString(StringPiece path, const string16& in_value);
  DictionaryValue* SetDictionary(StringPiece path,
                                 std::unique_ptr<DictionaryValue> in_value);
  ListValue* SetList(StringPiece path, std::unique_ptr<ListValue> in_value);

  // Like Set(), but without special treatment of '.'.  This allows e.g. URLs to
  // be used as paths.
  Value* SetWithoutPathExpansion(StringPiece key,
                                 std::unique_ptr<Value> in_value);

  // Convenience forms of SetWithoutPathExpansion().
  Value* SetBooleanWithoutPathExpansion(StringPiece path, bool in_value);
  Value* SetIntegerWithoutPathExpansion(StringPiece path, int in_value);
  Value* SetDoubleWithoutPathExpansion(StringPiece path, double in_value);
  Value* SetStringWithoutPathExpansion(StringPiece path, StringPiece in_value);
  Value* SetStringWithoutPathExpansion(StringPiece path,
                                       const string16& in_value);
  DictionaryValue* SetDictionaryWithoutPathExpansion(
      StringPiece path,
      std::unique_ptr<DictionaryValue> in_value);
  ListValue* SetListWithoutPathExpansion(StringPiece path,
                                         std::unique_ptr<ListValue> in_value);

  // Gets the Value associated with the given path starting from this object.
  // A path has the form "<key>" or "<key>.<key>.[...]", where "." indexes
  // into the next DictionaryValue down.  If the path can be resolved
  // successfully, the value for the last key in the path will be returned
  // through the |out_value| parameter, and the function will return true.
  // Otherwise, it will return false and |out_value| will be untouched.
  // Note that the dictionary always owns the value that's returned.
  // |out_value| is optional and will only be set if non-NULL.
  bool Get(StringPiece path, const Value** out_value) const;
  bool Get(StringPiece path, Value** out_value);

  // These are convenience forms of Get().  The value will be retrieved
  // and the return value will be true if the path is valid and the value at
  // the end of the path can be returned in the form specified.
  // |out_value| is optional and will only be set if non-NULL.
  bool GetBoolean(StringPiece path, bool* out_value) const;
  bool GetInteger(StringPiece path, int* out_value) const;
  // Values of both type Type::INTEGER and Type::DOUBLE can be obtained as
  // doubles.
  bool GetDouble(StringPiece path, double* out_value) const;
  bool GetString(StringPiece path, std::string* out_value) const;
  bool GetString(StringPiece path, string16* out_value) const;
  bool GetStringASCII(StringPiece path, std::string* out_value) const;
  bool GetBinary(StringPiece path, const Value** out_value) const;
  bool GetBinary(StringPiece path, Value** out_value);
  bool GetDictionary(StringPiece path,
                     const DictionaryValue** out_value) const;
  bool GetDictionary(StringPiece path, DictionaryValue** out_value);
  bool GetList(StringPiece path, const ListValue** out_value) const;
  bool GetList(StringPiece path, ListValue** out_value);

  // Like Get(), but without special treatment of '.'.  This allows e.g. URLs to
  // be used as paths.
  bool GetWithoutPathExpansion(StringPiece key, const Value** out_value) const;
  bool GetWithoutPathExpansion(StringPiece key, Value** out_value);
  bool GetBooleanWithoutPathExpansion(StringPiece key, bool* out_value) const;
  bool GetIntegerWithoutPathExpansion(StringPiece key, int* out_value) const;
  bool GetDoubleWithoutPathExpansion(StringPiece key, double* out_value) const;
  bool GetStringWithoutPathExpansion(StringPiece key,
                                     std::string* out_value) const;
  bool GetStringWithoutPathExpansion(StringPiece key,
                                     string16* out_value) const;
  bool GetDictionaryWithoutPathExpansion(
      StringPiece key,
      const DictionaryValue** out_value) const;
  bool GetDictionaryWithoutPathExpansion(StringPiece key,
                                         DictionaryValue** out_value);
  bool GetListWithoutPathExpansion(StringPiece key,
                                   const ListValue** out_value) const;
  bool GetListWithoutPathExpansion(StringPiece key, ListValue** out_value);

  // Removes the Value with the specified path from this dictionary (or one
  // of its child dictionaries, if the path is more than just a local key).
  // If |out_value| is non-NULL, the removed Value will be passed out via
  // |out_value|.  If |out_value| is NULL, the removed value will be deleted.
  // This method returns true if |path| is a valid path; otherwise it will
  // return false and the DictionaryValue object will be unchanged.
  bool Remove(StringPiece path, std::unique_ptr<Value>* out_value);

  // Like Remove(), but without special treatment of '.'.  This allows e.g. URLs
  // to be used as paths.
  bool RemoveWithoutPathExpansion(StringPiece key,
                                  std::unique_ptr<Value>* out_value);

  // Removes a path, clearing out all dictionaries on |path| that remain empty
  // after removing the value at |path|.
  bool RemovePath(StringPiece path, std::unique_ptr<Value>* out_value);

  // Makes a copy of |this| but doesn't include empty dictionaries and lists in
  // the copy.  This never returns NULL, even if |this| itself is empty.
  std::unique_ptr<DictionaryValue> DeepCopyWithoutEmptyChildren() const;

  // Merge |dictionary| into this dictionary. This is done recursively, i.e. any
  // sub-dictionaries will be merged as well. In case of key collisions, the
  // passed in dictionary takes precedence and data already present will be
  // replaced. Values within |dictionary| are deep-copied, so |dictionary| may
  // be freed any time after this call.
  void MergeDictionary(const DictionaryValue* dictionary);

  // Swaps contents with the |other| dictionary.
  void Swap(DictionaryValue* other);

  // This class provides an iterator over both keys and values in the
  // dictionary.  It can't be used to modify the dictionary.
  class BASE_EXPORT Iterator {
   public:
    explicit Iterator(const DictionaryValue& target);
    Iterator(const Iterator& other);
    ~Iterator();

    bool IsAtEnd() const { return it_ == target_.dict_->end(); }
    void Advance() { ++it_; }

    const std::string& key() const { return it_->first; }
    const Value& value() const { return *it_->second; }

   private:
    const DictionaryValue& target_;
    DictStorage::const_iterator it_;
  };

  // Iteration.
  iterator begin() { return dict_->begin(); }
  iterator end() { return dict_->end(); }

  const_iterator begin() const { return dict_->begin(); }
  const_iterator end() const { return dict_->end(); }

  // DEPRECATED, use DictionaryValue's copy constructor instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  DictionaryValue* DeepCopy() const;
  // DEPRECATED, use DictionaryValue's copy constructor instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  std::unique_ptr<DictionaryValue> CreateDeepCopy() const;
};

// This type of Value represents a list of other Value values.
class BASE_EXPORT ListValue : public Value {
 public:
  using const_iterator = ListStorage::const_iterator;
  using iterator = ListStorage::iterator;

  // Returns |value| if it is a list, nullptr otherwise.
  static std::unique_ptr<ListValue> From(std::unique_ptr<Value> value);

  ListValue();
  explicit ListValue(const ListStorage& in_list);
  explicit ListValue(ListStorage&& in_list) noexcept;

  // Clears the contents of this ListValue
  // DEPRECATED, use GetList()::clear() instead.
  void Clear();

  // Returns the number of Values in this list.
  // DEPRECATED, use GetList()::size() instead.
  size_t GetSize() const { return list_->size(); }

  // Returns the capacity of storage for Values in this list.
  // DEPRECATED, use GetList()::capacity() instead.
  size_t capacity() const { return list_->capacity(); }

  // Returns whether the list is empty.
  // DEPRECATED, use GetList()::empty() instead.
  bool empty() const { return list_->empty(); }

  // Reserves storage for at least |n| values.
  // DEPRECATED, use GetList()::reserve() instead.
  void Reserve(size_t n);

  // Sets the list item at the given index to be the Value specified by
  // the value given.  If the index beyond the current end of the list, null
  // Values will be used to pad out the list.
  // Returns true if successful, or false if the index was negative or
  // the value is a null pointer.
  // DEPRECATED, use GetList()::operator[] instead.
  bool Set(size_t index, std::unique_ptr<Value> in_value);

  // Gets the Value at the given index.  Modifies |out_value| (and returns true)
  // only if the index falls within the current list range.
  // Note that the list always owns the Value passed out via |out_value|.
  // |out_value| is optional and will only be set if non-NULL.
  // DEPRECATED, use GetList()::operator[] instead.
  bool Get(size_t index, const Value** out_value) const;
  bool Get(size_t index, Value** out_value);

  // Convenience forms of Get().  Modifies |out_value| (and returns true)
  // only if the index is valid and the Value at that index can be returned
  // in the specified form.
  // |out_value| is optional and will only be set if non-NULL.
  // DEPRECATED, use GetList()::operator[]::GetBool() instead.
  bool GetBoolean(size_t index, bool* out_value) const;
  // DEPRECATED, use GetList()::operator[]::GetInt() instead.
  bool GetInteger(size_t index, int* out_value) const;
  // Values of both type Type::INTEGER and Type::DOUBLE can be obtained as
  // doubles.
  // DEPRECATED, use GetList()::operator[]::GetDouble() instead.
  bool GetDouble(size_t index, double* out_value) const;
  // DEPRECATED, use GetList()::operator[]::GetString() instead.
  bool GetString(size_t index, std::string* out_value) const;
  bool GetString(size_t index, string16* out_value) const;
  // DEPRECATED, use GetList()::operator[]::GetBlob() instead.
  bool GetBinary(size_t index, const Value** out_value) const;
  bool GetBinary(size_t index, Value** out_value);

  bool GetDictionary(size_t index, const DictionaryValue** out_value) const;
  bool GetDictionary(size_t index, DictionaryValue** out_value);

  using Value::GetList;
  // DEPRECATED, use GetList()::operator[]::GetList() instead.
  bool GetList(size_t index, const ListValue** out_value) const;
  bool GetList(size_t index, ListValue** out_value);

  // Removes the Value with the specified index from this list.
  // If |out_value| is non-NULL, the removed Value AND ITS OWNERSHIP will be
  // passed out via |out_value|.  If |out_value| is NULL, the removed value will
  // be deleted.  This method returns true if |index| is valid; otherwise
  // it will return false and the ListValue object will be unchanged.
  // DEPRECATED, use GetList()::erase() instead.
  bool Remove(size_t index, std::unique_ptr<Value>* out_value);

  // Removes the first instance of |value| found in the list, if any, and
  // deletes it. |index| is the location where |value| was found. Returns false
  // if not found.
  // DEPRECATED, use GetList()::erase() instead.
  bool Remove(const Value& value, size_t* index);

  // Removes the element at |iter|. If |out_value| is NULL, the value will be
  // deleted, otherwise ownership of the value is passed back to the caller.
  // Returns an iterator pointing to the location of the element that
  // followed the erased element.
  // DEPRECATED, use GetList()::erase() instead.
  iterator Erase(iterator iter, std::unique_ptr<Value>* out_value);

  // Appends a Value to the end of the list.
  // DEPRECATED, use GetList()::push_back() instead.
  void Append(std::unique_ptr<Value> in_value);

  // Convenience forms of Append.
  // DEPRECATED, use GetList()::emplace_back() instead.
  void AppendBoolean(bool in_value);
  void AppendInteger(int in_value);
  void AppendDouble(double in_value);
  void AppendString(StringPiece in_value);
  void AppendString(const string16& in_value);
  // DEPRECATED, use GetList()::emplace_back() in a loop instead.
  void AppendStrings(const std::vector<std::string>& in_values);
  void AppendStrings(const std::vector<string16>& in_values);

  // Appends a Value if it's not already present. Returns true if successful,
  // or false if the value was already
  // DEPRECATED, use std::find() with GetList()::push_back() instead.
  bool AppendIfNotPresent(std::unique_ptr<Value> in_value);

  // Insert a Value at index.
  // Returns true if successful, or false if the index was out of range.
  // DEPRECATED, use GetList()::insert() instead.
  bool Insert(size_t index, std::unique_ptr<Value> in_value);

  // Searches for the first instance of |value| in the list using the Equals
  // method of the Value type.
  // Returns a const_iterator to the found item or to end() if none exists.
  // DEPRECATED, use std::find() instead.
  const_iterator Find(const Value& value) const;

  // Swaps contents with the |other| list.
  // DEPRECATED, use GetList()::swap() instead.
  void Swap(ListValue* other);

  // Iteration.
  // DEPRECATED, use GetList()::begin() instead.
  iterator begin() { return list_->begin(); }
  // DEPRECATED, use GetList()::end() instead.
  iterator end() { return list_->end(); }

  // DEPRECATED, use GetList()::begin() instead.
  const_iterator begin() const { return list_->begin(); }
  // DEPRECATED, use GetList()::end() instead.
  const_iterator end() const { return list_->end(); }

  // DEPRECATED, use ListValue's copy constructor instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  ListValue* DeepCopy() const;
  // DEPRECATED, use ListValue's copy constructor instead.
  // TODO(crbug.com/646113): Delete this and migrate callsites.
  std::unique_ptr<ListValue> CreateDeepCopy() const;
};

// This interface is implemented by classes that know how to serialize
// Value objects.
class BASE_EXPORT ValueSerializer {
 public:
  virtual ~ValueSerializer();

  virtual bool Serialize(const Value& root) = 0;
};

// This interface is implemented by classes that know how to deserialize Value
// objects.
class BASE_EXPORT ValueDeserializer {
 public:
  virtual ~ValueDeserializer();

  // This method deserializes the subclass-specific format into a Value object.
  // If the return value is non-NULL, the caller takes ownership of returned
  // Value. If the return value is NULL, and if error_code is non-NULL,
  // error_code will be set with the underlying error.
  // If |error_message| is non-null, it will be filled in with a formatted
  // error message including the location of the error if appropriate.
  virtual std::unique_ptr<Value> Deserialize(int* error_code,
                                             std::string* error_str) = 0;
};

// Stream operator so Values can be used in assertion statements.  In order that
// gtest uses this operator to print readable output on test failures, we must
// override each specific type. Otherwise, the default template implementation
// is preferred over an upcast.
BASE_EXPORT std::ostream& operator<<(std::ostream& out, const Value& value);

BASE_EXPORT inline std::ostream& operator<<(std::ostream& out,
                                            const DictionaryValue& value) {
  return out << static_cast<const Value&>(value);
}

BASE_EXPORT inline std::ostream& operator<<(std::ostream& out,
                                            const ListValue& value) {
  return out << static_cast<const Value&>(value);
}

// Stream operator so that enum class Types can be used in log statements.
BASE_EXPORT std::ostream& operator<<(std::ostream& out,
                                     const Value::Type& type);

}  // namespace base

#endif  // BASE_VALUES_H_

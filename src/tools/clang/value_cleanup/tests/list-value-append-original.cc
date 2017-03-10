// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "values.h"

#define true true

base::ListValue* ReturnsRawPtr() {
  return nullptr;
}

std::unique_ptr<base::Value> ReturnsUniquePtr() {
  return nullptr;
}

// The joy of raw pointers.
void DoesItTakeOwnership(base::Value*) {}

struct Thing {
  std::unique_ptr<base::Value> ToValue() { return nullptr; }
};

void F() {
  base::ListValue list;
  list.Append(new base::Value(1 == 0));
  list.Append(new base::Value(true));
  list.Append(new base::Value(static_cast<unsigned char>(1.0)));
  list.Append(new base::Value(double{3}));
  list.Append(new base::Value("abc"));

  list.Append(ReturnsUniquePtr().release());
  Thing thing;
  list.Append(thing.ToValue().release());
  std::unique_ptr<base::Value> unique_ptr_var;
  list.Append(unique_ptr_var.release());
}

void G(base::Value* input) {
  base::ListValue list;

  base::ListValue* local = new base::ListValue();
  // Not rewritten, since it often makes more sense to change the function
  // prototype.
  local->Append(input);
  // Should be rewritten: it will only be moved after it's no longer referenced.
  list.Append(local);

  // Not rewritten, since it would be used after it's moved. In theory, we could
  // automatically handle this too, but the risk of accidentally breaking
  // something is much higher.
  base::ListValue* clever_list = new base::ListValue;
  list.Append(clever_list);
  clever_list->AppendInteger(2);

  // Not rewritten, since it often makes more sense to change the function
  // prototype.
  base::Value* returned_value = ReturnsRawPtr();
  list.Append(returned_value);

  // Should be rewritten. The reassignment should be transformed into
  // .reset().
  base::ListValue* reused_list = new base::ListValue;
  reused_list->AppendInteger(1);
  list.Append(reused_list);
  reused_list = new base::ListValue;
  reused_list->AppendInteger(3);
  list.Append(reused_list);

  // This shouldn't be rewritten, since the reassignment is the return
  // value of a function.
  base::ListValue* reused_list_2 = new base::ListValue;
  reused_list_2->AppendInteger(4);
  list.Append(reused_list_2);
  reused_list_2 = ReturnsRawPtr();
  reused_list_2->AppendInteger(5);
  list.Append(reused_list_2);

  // auto should be expanded to a std::unique_ptr containing the deduced type.
  auto* auto_list = new base::ListValue;
  auto_list->AppendInteger(6);
  list.Append(auto_list);

  auto auto_list_2 = new base::ListValue;
  auto_list_2->AppendInteger(7);
  list.Append(auto_list_2);

  // Shouldn't be rewritten: a raw pointer is passed to a function which may or
  // may not take ownership.
  base::ListValue* maybe_owned_list = new base::ListValue;
  DoesItTakeOwnership(maybe_owned_list);
  list.Append(maybe_owned_list);

  // Should be rewritten, even though it doesn't have an initializer.
  base::ListValue* list_with_no_initializer;
  list_with_no_initializer = new base::ListValue;
  list.Append(list_with_no_initializer);

  // Make sure C++98 style initialization is correctly handled.
  base::ListValue* cxx98_list(new base::ListValue);
  list.Append(cxx98_list);

  // C++11 style syntax currently causes the tool to bail out: this is banned in
  // Chromium style anyway.
  base::ListValue* cxx11_list{new base::ListValue};
  list.Append(cxx11_list);
}

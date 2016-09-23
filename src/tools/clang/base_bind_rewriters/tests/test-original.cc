// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

template <typename>
class scoped_refptr {
 public:
  void* get() { return 0; }
};

namespace base {

template <typename Functor, typename... Args>
void Bind(Functor&&, Args&&...) {}

}  // namespace base

struct Foo {
  void Bar();
  static void Baz();
};

void Test() {
  using base::Bind;
  scoped_refptr<int> foo;
  base::Bind(&Foo::Bar, foo.get());
  Bind(&Foo::Bar, foo.get());
  base::Bind(&Foo::Bar, (&foo)->get());
  base::Bind(&Foo::Bar, foo.get(
       ));
  base::Bind(&Foo::Bar, foo
       .get());
  base::Bind(&Foo::Bar, foo.get(), foo.get());
  base::Bind(&Foo::Baz, foo.get());
  base::Bind(&Foo::Bar, foo.scoped_refptr<int>::get());
  base::Bind(&Foo::Bar, (&foo)->scoped_refptr<int>::get());
}

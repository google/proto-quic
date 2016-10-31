// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/optional.h"

#include <set>

#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

// Object used to test complex object with Optional<T> in addition of the move
// semantics.
class TestObject {
 public:
  enum class State {
    DEFAULT_CONSTRUCTED,
    VALUE_CONSTRUCTED,
    COPY_CONSTRUCTED,
    MOVE_CONSTRUCTED,
    MOVED_FROM,
    COPY_ASSIGNED,
    MOVE_ASSIGNED,
    SWAPPED,
  };

  TestObject() : foo_(0), bar_(0.0), state_(State::DEFAULT_CONSTRUCTED) {}

  TestObject(int foo, double bar)
      : foo_(foo), bar_(bar), state_(State::VALUE_CONSTRUCTED) {}

  TestObject(const TestObject& other)
      : foo_(other.foo_), bar_(other.bar_), state_(State::COPY_CONSTRUCTED) {}

  TestObject(TestObject&& other)
      : foo_(std::move(other.foo_)),
        bar_(std::move(other.bar_)),
        state_(State::MOVE_CONSTRUCTED) {
    other.state_ = State::MOVED_FROM;
  }

  TestObject& operator=(const TestObject& other) {
    foo_ = other.foo_;
    bar_ = other.bar_;
    state_ = State::COPY_ASSIGNED;
    return *this;
  }

  TestObject& operator=(TestObject&& other) {
    foo_ = other.foo_;
    bar_ = other.bar_;
    state_ = State::MOVE_ASSIGNED;
    other.state_ = State::MOVED_FROM;
    return *this;
  }

  void Swap(TestObject* other) {
    using std::swap;
    swap(foo_, other->foo_);
    swap(bar_, other->bar_);
    state_ = State::SWAPPED;
    other->state_ = State::SWAPPED;
  }

  bool operator==(const TestObject& other) const {
    return foo_ == other.foo_ && bar_ == other.bar_;
  }

  int foo() const { return foo_; }
  State state() const { return state_; }

 private:
  int foo_;
  double bar_;
  State state_;
};

// Implementing Swappable concept.
void swap(TestObject& lhs, TestObject& rhs) {
  lhs.Swap(&rhs);
}

class NonTriviallyDestructible {
  ~NonTriviallyDestructible() {}
};

}  // anonymous namespace

static_assert(is_trivially_destructible<Optional<int>>::value,
              "OptionalIsTriviallyDestructible");

static_assert(
    !is_trivially_destructible<Optional<NonTriviallyDestructible>>::value,
    "OptionalIsTriviallyDestructible");

TEST(OptionalTest, DefaultConstructor) {
  {
    constexpr Optional<float> o;
    EXPECT_FALSE(o);
  }

  {
    Optional<std::string> o;
    EXPECT_FALSE(o);
  }

  {
    Optional<TestObject> o;
    EXPECT_FALSE(o);
  }
}

TEST(OptionalTest, CopyConstructor) {
  {
    Optional<float> first(0.1f);
    Optional<float> other(first);

    EXPECT_TRUE(other);
    EXPECT_EQ(other.value(), 0.1f);
    EXPECT_EQ(first, other);
  }

  {
    Optional<std::string> first("foo");
    Optional<std::string> other(first);

    EXPECT_TRUE(other);
    EXPECT_EQ(other.value(), "foo");
    EXPECT_EQ(first, other);
  }

  {
    Optional<TestObject> first(TestObject(3, 0.1));
    Optional<TestObject> other(first);

    EXPECT_TRUE(!!other);
    EXPECT_TRUE(other.value() == TestObject(3, 0.1));
    EXPECT_TRUE(first == other);
  }
}

TEST(OptionalTest, ValueConstructor) {
  {
    constexpr float value = 0.1f;
    constexpr Optional<float> o(value);

    EXPECT_TRUE(o);
    EXPECT_EQ(value, o.value());
  }

  {
    std::string value("foo");
    Optional<std::string> o(value);

    EXPECT_TRUE(o);
    EXPECT_EQ(value, o.value());
  }

  {
    TestObject value(3, 0.1);
    Optional<TestObject> o(value);

    EXPECT_TRUE(o);
    EXPECT_EQ(TestObject::State::COPY_CONSTRUCTED, o->state());
    EXPECT_EQ(value, o.value());
  }
}

TEST(OptionalTest, MoveConstructor) {
  {
    Optional<float> first(0.1f);
    Optional<float> second(std::move(first));

    EXPECT_TRUE(second);
    EXPECT_EQ(second.value(), 0.1f);

    EXPECT_TRUE(first);
  }

  {
    Optional<std::string> first("foo");
    Optional<std::string> second(std::move(first));

    EXPECT_TRUE(second);
    EXPECT_EQ("foo", second.value());

    EXPECT_TRUE(first);
  }

  {
    Optional<TestObject> first(TestObject(3, 0.1));
    Optional<TestObject> second(std::move(first));

    EXPECT_TRUE(!!second);
    EXPECT_EQ(TestObject::State::MOVE_CONSTRUCTED, second->state());
    EXPECT_TRUE(TestObject(3, 0.1) == second.value());

    EXPECT_TRUE(!!first);
    EXPECT_EQ(TestObject::State::MOVED_FROM, first->state());
  }
}

TEST(OptionalTest, MoveValueConstructor) {
  {
    float value = 0.1f;
    Optional<float> o(std::move(value));

    EXPECT_TRUE(o);
    EXPECT_EQ(0.1f, o.value());
  }

  {
    std::string value("foo");
    Optional<std::string> o(std::move(value));

    EXPECT_TRUE(o);
    EXPECT_EQ("foo", o.value());
  }

  {
    TestObject value(3, 0.1);
    Optional<TestObject> o(std::move(value));

    EXPECT_TRUE(o);
    EXPECT_EQ(TestObject::State::MOVE_CONSTRUCTED, o->state());
    EXPECT_EQ(TestObject(3, 0.1), o.value());
  }
}

TEST(OptionalTest, ConstructorForwardArguments) {
  {
    Optional<float> a(base::in_place, 0.1f);
    EXPECT_TRUE(a);
    EXPECT_EQ(0.1f, a.value());
  }

  {
    Optional<std::string> a(base::in_place, "foo");
    EXPECT_TRUE(a);
    EXPECT_EQ("foo", a.value());
  }

  {
    Optional<TestObject> a(base::in_place, 0, 0.1);
    EXPECT_TRUE(!!a);
    EXPECT_TRUE(TestObject(0, 0.1) == a.value());
  }
}

TEST(OptionalTest, NulloptConstructor) {
  constexpr Optional<int> a(base::nullopt);
  EXPECT_FALSE(a);
}

TEST(OptionalTest, AssignValue) {
  {
    Optional<float> a;
    EXPECT_FALSE(a);
    a = 0.1f;
    EXPECT_TRUE(a);

    Optional<float> b(0.1f);
    EXPECT_TRUE(a == b);
  }

  {
    Optional<std::string> a;
    EXPECT_FALSE(a);
    a = std::string("foo");
    EXPECT_TRUE(a);

    Optional<std::string> b(std::string("foo"));
    EXPECT_EQ(a, b);
  }

  {
    Optional<TestObject> a;
    EXPECT_FALSE(!!a);
    a = TestObject(3, 0.1);
    EXPECT_TRUE(!!a);

    Optional<TestObject> b(TestObject(3, 0.1));
    EXPECT_TRUE(a == b);
  }

  {
    Optional<TestObject> a = TestObject(4, 1.0);
    EXPECT_TRUE(!!a);
    a = TestObject(3, 0.1);
    EXPECT_TRUE(!!a);

    Optional<TestObject> b(TestObject(3, 0.1));
    EXPECT_TRUE(a == b);
  }
}

TEST(OptionalTest, AssignObject) {
  {
    Optional<float> a;
    Optional<float> b(0.1f);
    a = b;

    EXPECT_TRUE(a);
    EXPECT_EQ(a.value(), 0.1f);
    EXPECT_EQ(a, b);
  }

  {
    Optional<std::string> a;
    Optional<std::string> b("foo");
    a = b;

    EXPECT_TRUE(a);
    EXPECT_EQ(a.value(), "foo");
    EXPECT_EQ(a, b);
  }

  {
    Optional<TestObject> a;
    Optional<TestObject> b(TestObject(3, 0.1));
    a = b;

    EXPECT_TRUE(!!a);
    EXPECT_TRUE(a.value() == TestObject(3, 0.1));
    EXPECT_TRUE(a == b);
  }

  {
    Optional<TestObject> a(TestObject(4, 1.0));
    Optional<TestObject> b(TestObject(3, 0.1));
    a = b;

    EXPECT_TRUE(!!a);
    EXPECT_TRUE(a.value() == TestObject(3, 0.1));
    EXPECT_TRUE(a == b);
  }
}

TEST(OptionalTest, AssignObject_rvalue) {
  {
    Optional<float> a;
    Optional<float> b(0.1f);
    a = std::move(b);

    EXPECT_TRUE(a);
    EXPECT_TRUE(b);
    EXPECT_EQ(0.1f, a.value());
  }

  {
    Optional<std::string> a;
    Optional<std::string> b("foo");
    a = std::move(b);

    EXPECT_TRUE(a);
    EXPECT_TRUE(b);
    EXPECT_EQ("foo", a.value());
  }

  {
    Optional<TestObject> a;
    Optional<TestObject> b(TestObject(3, 0.1));
    a = std::move(b);

    EXPECT_TRUE(!!a);
    EXPECT_TRUE(!!b);
    EXPECT_TRUE(TestObject(3, 0.1) == a.value());

    EXPECT_EQ(TestObject::State::MOVE_CONSTRUCTED, a->state());
    EXPECT_EQ(TestObject::State::MOVED_FROM, b->state());
  }

  {
    Optional<TestObject> a(TestObject(4, 1.0));
    Optional<TestObject> b(TestObject(3, 0.1));
    a = std::move(b);

    EXPECT_TRUE(!!a);
    EXPECT_TRUE(!!b);
    EXPECT_TRUE(TestObject(3, 0.1) == a.value());

    EXPECT_EQ(TestObject::State::MOVE_ASSIGNED, a->state());
    EXPECT_EQ(TestObject::State::MOVED_FROM, b->state());
  }
}

TEST(OptionalTest, AssignNull) {
  {
    Optional<float> a(0.1f);
    Optional<float> b(0.2f);
    a = base::nullopt;
    b = base::nullopt;
    EXPECT_EQ(a, b);
  }

  {
    Optional<std::string> a("foo");
    Optional<std::string> b("bar");
    a = base::nullopt;
    b = base::nullopt;
    EXPECT_EQ(a, b);
  }

  {
    Optional<TestObject> a(TestObject(3, 0.1));
    Optional<TestObject> b(TestObject(4, 1.0));
    a = base::nullopt;
    b = base::nullopt;
    EXPECT_TRUE(a == b);
  }
}

TEST(OptionalTest, OperatorStar) {
  {
    Optional<float> a(0.1f);
    EXPECT_EQ(a.value(), *a);
  }

  {
    Optional<std::string> a("foo");
    EXPECT_EQ(a.value(), *a);
  }

  {
    Optional<TestObject> a(TestObject(3, 0.1));
    EXPECT_EQ(a.value(), *a);
  }
}

TEST(OptionalTest, OperatorStar_rvalue) {
  EXPECT_EQ(0.1f, *Optional<float>(0.1f));
  EXPECT_EQ(std::string("foo"), *Optional<std::string>("foo"));
  EXPECT_TRUE(TestObject(3, 0.1) == *Optional<TestObject>(TestObject(3, 0.1)));
}

TEST(OptionalTest, OperatorArrow) {
  Optional<TestObject> a(TestObject(3, 0.1));
  EXPECT_EQ(a->foo(), 3);
}

TEST(OptionalTest, Value_rvalue) {
  EXPECT_EQ(0.1f, Optional<float>(0.1f).value());
  EXPECT_EQ(std::string("foo"), Optional<std::string>("foo").value());
  EXPECT_TRUE(TestObject(3, 0.1) ==
              Optional<TestObject>(TestObject(3, 0.1)).value());
}

TEST(OptionalTest, ValueOr) {
  {
    Optional<float> a;
    EXPECT_EQ(0.0f, a.value_or(0.0f));

    a = 0.1f;
    EXPECT_EQ(0.1f, a.value_or(0.0f));

    a = base::nullopt;
    EXPECT_EQ(0.0f, a.value_or(0.0f));
  }

  {
    Optional<std::string> a;
    EXPECT_EQ("bar", a.value_or("bar"));

    a = std::string("foo");
    EXPECT_EQ(std::string("foo"), a.value_or("bar"));

    a = base::nullopt;
    EXPECT_EQ(std::string("bar"), a.value_or("bar"));
  }

  {
    Optional<TestObject> a;
    EXPECT_TRUE(a.value_or(TestObject(1, 0.3)) == TestObject(1, 0.3));

    a = TestObject(3, 0.1);
    EXPECT_TRUE(a.value_or(TestObject(1, 0.3)) == TestObject(3, 0.1));

    a = base::nullopt;
    EXPECT_TRUE(a.value_or(TestObject(1, 0.3)) == TestObject(1, 0.3));
  }
}

TEST(OptionalTest, Swap_bothNoValue) {
  Optional<TestObject> a, b;
  a.swap(b);

  EXPECT_FALSE(a);
  EXPECT_FALSE(b);
  EXPECT_TRUE(TestObject(42, 0.42) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(42, 0.42) == b.value_or(TestObject(42, 0.42)));
}

TEST(OptionalTest, Swap_inHasValue) {
  Optional<TestObject> a(TestObject(1, 0.3));
  Optional<TestObject> b;
  a.swap(b);

  EXPECT_FALSE(a);

  EXPECT_TRUE(!!b);
  EXPECT_TRUE(TestObject(42, 0.42) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(1, 0.3) == b.value_or(TestObject(42, 0.42)));
}

TEST(OptionalTest, Swap_outHasValue) {
  Optional<TestObject> a;
  Optional<TestObject> b(TestObject(1, 0.3));
  a.swap(b);

  EXPECT_TRUE(!!a);
  EXPECT_FALSE(!!b);
  EXPECT_TRUE(TestObject(1, 0.3) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(42, 0.42) == b.value_or(TestObject(42, 0.42)));
}

TEST(OptionalTest, Swap_bothValue) {
  Optional<TestObject> a(TestObject(0, 0.1));
  Optional<TestObject> b(TestObject(1, 0.3));
  a.swap(b);

  EXPECT_TRUE(!!a);
  EXPECT_TRUE(!!b);
  EXPECT_TRUE(TestObject(1, 0.3) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(0, 0.1) == b.value_or(TestObject(42, 0.42)));
  EXPECT_EQ(TestObject::State::SWAPPED, a->state());
  EXPECT_EQ(TestObject::State::SWAPPED, b->state());
}

TEST(OptionalTest, Emplace) {
  {
    Optional<float> a(0.1f);
    a.emplace(0.3f);

    EXPECT_TRUE(a);
    EXPECT_EQ(0.3f, a.value());
  }

  {
    Optional<std::string> a("foo");
    a.emplace("bar");

    EXPECT_TRUE(a);
    EXPECT_EQ("bar", a.value());
  }

  {
    Optional<TestObject> a(TestObject(0, 0.1));
    a.emplace(TestObject(1, 0.2));

    EXPECT_TRUE(!!a);
    EXPECT_TRUE(TestObject(1, 0.2) == a.value());
  }
}

TEST(OptionalTest, Equals_TwoEmpty) {
  Optional<int> a;
  Optional<int> b;

  EXPECT_TRUE(a == b);
}

TEST(OptionalTest, Equals_TwoEquals) {
  Optional<int> a(1);
  Optional<int> b(1);

  EXPECT_TRUE(a == b);
}

TEST(OptionalTest, Equals_OneEmpty) {
  Optional<int> a;
  Optional<int> b(1);

  EXPECT_FALSE(a == b);
}

TEST(OptionalTest, Equals_TwoDifferent) {
  Optional<int> a(0);
  Optional<int> b(1);

  EXPECT_FALSE(a == b);
}

TEST(OptionalTest, NotEquals_TwoEmpty) {
  Optional<int> a;
  Optional<int> b;

  EXPECT_FALSE(a != b);
}

TEST(OptionalTest, NotEquals_TwoEquals) {
  Optional<int> a(1);
  Optional<int> b(1);

  EXPECT_FALSE(a != b);
}

TEST(OptionalTest, NotEquals_OneEmpty) {
  Optional<int> a;
  Optional<int> b(1);

  EXPECT_TRUE(a != b);
}

TEST(OptionalTest, NotEquals_TwoDifferent) {
  Optional<int> a(0);
  Optional<int> b(1);

  EXPECT_TRUE(a != b);
}

TEST(OptionalTest, Less_LeftEmpty) {
  Optional<int> l;
  Optional<int> r(1);

  EXPECT_TRUE(l < r);
}

TEST(OptionalTest, Less_RightEmpty) {
  Optional<int> l(1);
  Optional<int> r;

  EXPECT_FALSE(l < r);
}

TEST(OptionalTest, Less_BothEmpty) {
  Optional<int> l;
  Optional<int> r;

  EXPECT_FALSE(l < r);
}

TEST(OptionalTest, Less_BothValues) {
  {
    Optional<int> l(1);
    Optional<int> r(2);

    EXPECT_TRUE(l < r);
  }
  {
    Optional<int> l(2);
    Optional<int> r(1);

    EXPECT_FALSE(l < r);
  }
  {
    Optional<int> l(1);
    Optional<int> r(1);

    EXPECT_FALSE(l < r);
  }
}

TEST(OptionalTest, LessEq_LeftEmpty) {
  Optional<int> l;
  Optional<int> r(1);

  EXPECT_TRUE(l <= r);
}

TEST(OptionalTest, LessEq_RightEmpty) {
  Optional<int> l(1);
  Optional<int> r;

  EXPECT_FALSE(l <= r);
}

TEST(OptionalTest, LessEq_BothEmpty) {
  Optional<int> l;
  Optional<int> r;

  EXPECT_TRUE(l <= r);
}

TEST(OptionalTest, LessEq_BothValues) {
  {
    Optional<int> l(1);
    Optional<int> r(2);

    EXPECT_TRUE(l <= r);
  }
  {
    Optional<int> l(2);
    Optional<int> r(1);

    EXPECT_FALSE(l <= r);
  }
  {
    Optional<int> l(1);
    Optional<int> r(1);

    EXPECT_TRUE(l <= r);
  }
}

TEST(OptionalTest, Greater_BothEmpty) {
  Optional<int> l;
  Optional<int> r;

  EXPECT_FALSE(l > r);
}

TEST(OptionalTest, Greater_LeftEmpty) {
  Optional<int> l;
  Optional<int> r(1);

  EXPECT_FALSE(l > r);
}

TEST(OptionalTest, Greater_RightEmpty) {
  Optional<int> l(1);
  Optional<int> r;

  EXPECT_TRUE(l > r);
}

TEST(OptionalTest, Greater_BothValue) {
  {
    Optional<int> l(1);
    Optional<int> r(2);

    EXPECT_FALSE(l > r);
  }
  {
    Optional<int> l(2);
    Optional<int> r(1);

    EXPECT_TRUE(l > r);
  }
  {
    Optional<int> l(1);
    Optional<int> r(1);

    EXPECT_FALSE(l > r);
  }
}

TEST(OptionalTest, GreaterEq_BothEmpty) {
  Optional<int> l;
  Optional<int> r;

  EXPECT_TRUE(l >= r);
}

TEST(OptionalTest, GreaterEq_LeftEmpty) {
  Optional<int> l;
  Optional<int> r(1);

  EXPECT_FALSE(l >= r);
}

TEST(OptionalTest, GreaterEq_RightEmpty) {
  Optional<int> l(1);
  Optional<int> r;

  EXPECT_TRUE(l >= r);
}

TEST(OptionalTest, GreaterEq_BothValue) {
  {
    Optional<int> l(1);
    Optional<int> r(2);

    EXPECT_FALSE(l >= r);
  }
  {
    Optional<int> l(2);
    Optional<int> r(1);

    EXPECT_TRUE(l >= r);
  }
  {
    Optional<int> l(1);
    Optional<int> r(1);

    EXPECT_TRUE(l >= r);
  }
}

TEST(OptionalTest, OptNullEq) {
  {
    Optional<int> opt;
    EXPECT_TRUE(opt == base::nullopt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(opt == base::nullopt);
  }
}

TEST(OptionalTest, NullOptEq) {
  {
    Optional<int> opt;
    EXPECT_TRUE(base::nullopt == opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(base::nullopt == opt);
  }
}

TEST(OptionalTest, OptNullNotEq) {
  {
    Optional<int> opt;
    EXPECT_FALSE(opt != base::nullopt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(opt != base::nullopt);
  }
}

TEST(OptionalTest, NullOptNotEq) {
  {
    Optional<int> opt;
    EXPECT_FALSE(base::nullopt != opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(base::nullopt != opt);
  }
}

TEST(OptionalTest, OptNullLower) {
  {
    Optional<int> opt;
    EXPECT_FALSE(opt < base::nullopt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(opt < base::nullopt);
  }
}

TEST(OptionalTest, NullOptLower) {
  {
    Optional<int> opt;
    EXPECT_FALSE(base::nullopt < opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(base::nullopt < opt);
  }
}

TEST(OptionalTest, OptNullLowerEq) {
  {
    Optional<int> opt;
    EXPECT_TRUE(opt <= base::nullopt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(opt <= base::nullopt);
  }
}

TEST(OptionalTest, NullOptLowerEq) {
  {
    Optional<int> opt;
    EXPECT_TRUE(base::nullopt <= opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(base::nullopt <= opt);
  }
}

TEST(OptionalTest, OptNullGreater) {
  {
    Optional<int> opt;
    EXPECT_FALSE(opt > base::nullopt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(opt > base::nullopt);
  }
}

TEST(OptionalTest, NullOptGreater) {
  {
    Optional<int> opt;
    EXPECT_FALSE(base::nullopt > opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(base::nullopt > opt);
  }
}

TEST(OptionalTest, OptNullGreaterEq) {
  {
    Optional<int> opt;
    EXPECT_TRUE(opt >= base::nullopt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(opt >= base::nullopt);
  }
}

TEST(OptionalTest, NullOptGreaterEq) {
  {
    Optional<int> opt;
    EXPECT_TRUE(base::nullopt >= opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(base::nullopt >= opt);
  }
}

TEST(OptionalTest, ValueEq_Empty) {
  Optional<int> opt;
  EXPECT_FALSE(opt == 1);
}

TEST(OptionalTest, ValueEq_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_FALSE(opt == 1);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(opt == 1);
  }
}

TEST(OptionalTest, EqValue_Empty) {
  Optional<int> opt;
  EXPECT_FALSE(1 == opt);
}

TEST(OptionalTest, EqValue_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_FALSE(1 == opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(1 == opt);
  }
}

TEST(OptionalTest, ValueNotEq_Empty) {
  Optional<int> opt;
  EXPECT_TRUE(opt != 1);
}

TEST(OptionalTest, ValueNotEq_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_TRUE(opt != 1);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(opt != 1);
  }
}

TEST(OptionalTest, NotEqValue_Empty) {
  Optional<int> opt;
  EXPECT_TRUE(1 != opt);
}

TEST(OptionalTest, NotEqValue_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_TRUE(1 != opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(1 != opt);
  }
}

TEST(OptionalTest, ValueLess_Empty) {
  Optional<int> opt;
  EXPECT_TRUE(opt < 1);
}

TEST(OptionalTest, ValueLess_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_TRUE(opt < 1);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(opt < 1);
  }
  {
    Optional<int> opt(2);
    EXPECT_FALSE(opt < 1);
  }
}

TEST(OptionalTest, LessValue_Empty) {
  Optional<int> opt;
  EXPECT_FALSE(1 < opt);
}

TEST(OptionalTest, LessValue_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_FALSE(1 < opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(1 < opt);
  }
  {
    Optional<int> opt(2);
    EXPECT_TRUE(1 < opt);
  }
}

TEST(OptionalTest, ValueLessEq_Empty) {
  Optional<int> opt;
  EXPECT_TRUE(opt <= 1);
}

TEST(OptionalTest, ValueLessEq_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_TRUE(opt <= 1);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(opt <= 1);
  }
  {
    Optional<int> opt(2);
    EXPECT_FALSE(opt <= 1);
  }
}

TEST(OptionalTest, LessEqValue_Empty) {
  Optional<int> opt;
  EXPECT_FALSE(1 <= opt);
}

TEST(OptionalTest, LessEqValue_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_FALSE(1 <= opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(1 <= opt);
  }
  {
    Optional<int> opt(2);
    EXPECT_TRUE(1 <= opt);
  }
}

TEST(OptionalTest, ValueGreater_Empty) {
  Optional<int> opt;
  EXPECT_FALSE(opt > 1);
}

TEST(OptionalTest, ValueGreater_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_FALSE(opt > 1);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(opt > 1);
  }
  {
    Optional<int> opt(2);
    EXPECT_TRUE(opt > 1);
  }
}

TEST(OptionalTest, GreaterValue_Empty) {
  Optional<int> opt;
  EXPECT_TRUE(1 > opt);
}

TEST(OptionalTest, GreaterValue_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_TRUE(1 > opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_FALSE(1 > opt);
  }
  {
    Optional<int> opt(2);
    EXPECT_FALSE(1 > opt);
  }
}

TEST(OptionalTest, ValueGreaterEq_Empty) {
  Optional<int> opt;
  EXPECT_FALSE(opt >= 1);
}

TEST(OptionalTest, ValueGreaterEq_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_FALSE(opt >= 1);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(opt >= 1);
  }
  {
    Optional<int> opt(2);
    EXPECT_TRUE(opt >= 1);
  }
}

TEST(OptionalTest, GreaterEqValue_Empty) {
  Optional<int> opt;
  EXPECT_TRUE(1 >= opt);
}

TEST(OptionalTest, GreaterEqValue_NotEmpty) {
  {
    Optional<int> opt(0);
    EXPECT_TRUE(1 >= opt);
  }
  {
    Optional<int> opt(1);
    EXPECT_TRUE(1 >= opt);
  }
  {
    Optional<int> opt(2);
    EXPECT_FALSE(1 >= opt);
  }
}

TEST(OptionalTest, NotEquals) {
  {
    Optional<float> a(0.1f);
    Optional<float> b(0.2f);
    EXPECT_NE(a, b);
  }

  {
    Optional<std::string> a("foo");
    Optional<std::string> b("bar");
    EXPECT_NE(a, b);
  }

  {
    Optional<TestObject> a(TestObject(3, 0.1));
    Optional<TestObject> b(TestObject(4, 1.0));
    EXPECT_TRUE(a != b);
  }
}

TEST(OptionalTest, NotEqualsNull) {
  {
    Optional<float> a(0.1f);
    Optional<float> b(0.1f);
    b = base::nullopt;
    EXPECT_NE(a, b);
  }

  {
    Optional<std::string> a("foo");
    Optional<std::string> b("foo");
    b = base::nullopt;
    EXPECT_NE(a, b);
  }

  {
    Optional<TestObject> a(TestObject(3, 0.1));
    Optional<TestObject> b(TestObject(3, 0.1));
    b = base::nullopt;
    EXPECT_TRUE(a != b);
  }
}

TEST(OptionalTest, MakeOptional) {
  {
    Optional<float> o = base::make_optional(32.f);
    EXPECT_TRUE(o);
    EXPECT_EQ(32.f, *o);

    float value = 3.f;
    o = base::make_optional(std::move(value));
    EXPECT_TRUE(o);
    EXPECT_EQ(3.f, *o);
  }

  {
    Optional<std::string> o = base::make_optional(std::string("foo"));
    EXPECT_TRUE(o);
    EXPECT_EQ("foo", *o);

    std::string value = "bar";
    o = base::make_optional(std::move(value));
    EXPECT_TRUE(o);
    EXPECT_EQ(std::string("bar"), *o);
  }

  {
    Optional<TestObject> o = base::make_optional(TestObject(3, 0.1));
    EXPECT_TRUE(!!o);
    EXPECT_TRUE(TestObject(3, 0.1) == *o);

    TestObject value = TestObject(0, 0.42);
    o = base::make_optional(std::move(value));
    EXPECT_TRUE(!!o);
    EXPECT_TRUE(TestObject(0, 0.42) == *o);
    EXPECT_EQ(TestObject::State::MOVED_FROM, value.state());
    EXPECT_EQ(TestObject::State::MOVE_ASSIGNED, o->state());

    EXPECT_EQ(TestObject::State::MOVE_CONSTRUCTED,
              base::make_optional(std::move(value))->state());
  }
}

TEST(OptionalTest, NonMemberSwap_bothNoValue) {
  Optional<TestObject> a, b;
  base::swap(a, b);

  EXPECT_FALSE(!!a);
  EXPECT_FALSE(!!b);
  EXPECT_TRUE(TestObject(42, 0.42) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(42, 0.42) == b.value_or(TestObject(42, 0.42)));
}

TEST(OptionalTest, NonMemberSwap_inHasValue) {
  Optional<TestObject> a(TestObject(1, 0.3));
  Optional<TestObject> b;
  base::swap(a, b);

  EXPECT_FALSE(!!a);
  EXPECT_TRUE(!!b);
  EXPECT_TRUE(TestObject(42, 0.42) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(1, 0.3) == b.value_or(TestObject(42, 0.42)));
}

TEST(OptionalTest, NonMemberSwap_outHasValue) {
  Optional<TestObject> a;
  Optional<TestObject> b(TestObject(1, 0.3));
  base::swap(a, b);

  EXPECT_TRUE(!!a);
  EXPECT_FALSE(!!b);
  EXPECT_TRUE(TestObject(1, 0.3) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(42, 0.42) == b.value_or(TestObject(42, 0.42)));
}

TEST(OptionalTest, NonMemberSwap_bothValue) {
  Optional<TestObject> a(TestObject(0, 0.1));
  Optional<TestObject> b(TestObject(1, 0.3));
  base::swap(a, b);

  EXPECT_TRUE(!!a);
  EXPECT_TRUE(!!b);
  EXPECT_TRUE(TestObject(1, 0.3) == a.value_or(TestObject(42, 0.42)));
  EXPECT_TRUE(TestObject(0, 0.1) == b.value_or(TestObject(42, 0.42)));
  EXPECT_EQ(TestObject::State::SWAPPED, a->state());
  EXPECT_EQ(TestObject::State::SWAPPED, b->state());
}

TEST(OptionalTest, Hash_OptionalReflectsInternal) {
  {
    std::hash<int> int_hash;
    std::hash<Optional<int>> opt_int_hash;

    EXPECT_EQ(int_hash(1), opt_int_hash(Optional<int>(1)));
  }

  {
    std::hash<std::string> str_hash;
    std::hash<Optional<std::string>> opt_str_hash;

    EXPECT_EQ(str_hash(std::string("foobar")),
              opt_str_hash(Optional<std::string>(std::string("foobar"))));
  }
}

TEST(OptionalTest, Hash_NullOptEqualsNullOpt) {
  std::hash<Optional<int>> opt_int_hash;
  std::hash<Optional<std::string>> opt_str_hash;

  EXPECT_EQ(opt_str_hash(Optional<std::string>()),
            opt_int_hash(Optional<int>()));
}

TEST(OptionalTest, Hash_UseInSet) {
  std::set<Optional<int>> setOptInt;

  EXPECT_EQ(setOptInt.end(), setOptInt.find(42));

  setOptInt.insert(Optional<int>(3));
  EXPECT_EQ(setOptInt.end(), setOptInt.find(42));
  EXPECT_NE(setOptInt.end(), setOptInt.find(3));
}

TEST(OptionalTest, HasValue) {
  Optional<int> a;
  EXPECT_FALSE(a.has_value());

  a = 42;
  EXPECT_TRUE(a.has_value());

  a = nullopt;
  EXPECT_FALSE(a.has_value());

  a = 0;
  EXPECT_TRUE(a.has_value());

  a = Optional<int>();
  EXPECT_FALSE(a.has_value());
}

TEST(OptionalTest, Reset_int) {
  Optional<int> a(0);
  EXPECT_TRUE(a.has_value());
  EXPECT_EQ(0, a.value());

  a.reset();
  EXPECT_FALSE(a.has_value());
  EXPECT_EQ(-1, a.value_or(-1));
}

TEST(OptionalTest, Reset_Object) {
  Optional<TestObject> a(TestObject(0, 0.1));
  EXPECT_TRUE(a.has_value());
  EXPECT_EQ(TestObject(0, 0.1), a.value());

  a.reset();
  EXPECT_FALSE(a.has_value());
  EXPECT_EQ(TestObject(42, 0.0), a.value_or(TestObject(42, 0.0)));
}

TEST(OptionalTest, Reset_NoOp) {
  Optional<int> a;
  EXPECT_FALSE(a.has_value());

  a.reset();
  EXPECT_FALSE(a.has_value());
}

}  // namespace base

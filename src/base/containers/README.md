# base/containers library

## What goes here

This directory contains some STL-like containers.

Things should be moved here that are generally applicable across the code base.
Don't add things here just because you need them in one place and think others
may someday want something similar. You can put specialized containers in
your component's directory and we can promote them here later if we feel there
is broad applicability.

### Design and naming

Containers should adhere as closely to STL as possible. Functions and behaviors
not present in STL should only be added when they are related to the specific
data structure implemented by the container.

For STL-like containers our policy is that they should use STL-like naming even
when it may conflict with the style guide. So functions and class names should
be lower case with underscores. Non-STL-like classes and functions should use
Google naming. Be sure to use the base namespace.

## Map and set selection

### Usage advice

  * Generally avoid **std::unordered\_set** and **std::unordered\_map**. In the
    common case, query performance is unlikely to be sufficiently higher than
    std::map to make a difference, insert performance is slightly worse, and
    the memory overhead is high. This makes sense mostly for large tables where
    you expect a lot of lookups.

  * Most maps and sets in Chrome are small and contain objects that can be
    moved efficiently. In this case, consider **base::flat\_map** and
    **base::flat\_set**. You need to be aware of the maximum expected size of
    the container since individual inserts and deletes are O(n), giving O(n^2)
    construction time for the entire map. But because it avoids mallocs in most
    cases, inserts are better or comparable to other containers even for
    several dozen items, and efficiently-moved types are unlikely to have
    performance problems for most cases until you have hundreds of items. If
    your container can be constructed in one shot, the constructor from vector
    gives O(n log n) construction times and it should be strictly better than
    a std::map.

  * **base::small\_map** has better runtime memory usage without the poor
    mutation performance of large containers that base::flat\_map has. But this
    advantage is partially offset by additional code size. Prefer in cases
    where you make�many objects so that the code/heap tradeoff is good.

  * Use **std::map** and **std::set** if you can't decide. Even if they're not
    great, they're unlikely to be bad or surprising.

### Map and set details

Sizes are on 64-bit platforms. Stable iterators aren't invalidated when the
container is mutated.

| Container                                | Empty size            | Per-item overhead | Stable iterators? |
|:---------------------------------------- |:--------------------- |:----------------- |:----------------- |
| std::map, std::set                       | 16 bytes              | 32 bytes          | Yes               |
| std::unordered\_map, std::unordered\_set | 128 bytes             | 16-24 bytes       | No                |
| base::flat\_map and base::flat\_set      | 24 bytes              | 0 (see notes)     | No                |
| base::small\_map                         | 24 bytes (see notes)  | 32 bytes          | No                |

**Takeaways:** std::unordered\_map and std::unordered\_map have high
overhead for small container sizes, prefer these only for larger workloads.

Code size comparisons for a block of code (see appendix) on Windows using
strings as keys.

| Container           | Code size  |
|:------------------- |:---------- |
| std::unordered\_map | 1646 bytes |
| std::map            | 1759 bytes |
| base::flat\_map     | 1872 bytes |
| base::small\_map    | 2410 bytes |

**Takeaways:** base::small\_map generates more code because of the inlining of
both brute-force and red-black tree searching. This makes it less attractive
for random one-off uses. But if your code is called frequently, the runtime
memory benefits will be more important. The code sizes of the other maps are
close enough it's not worth worrying about.

### std::map and std::set

A red-black tree. Each inserted item requires the memory allocation of a node
on the heap. Each node contains a left pointer, a right pointer, a parent
pointer, and a "color" for the red-black tree (32-bytes per item on 64-bits).

### std::unordered\_map and std::unordered\_set

A hash table. Implemented on Windows as a std::vector + std::list and in libc++
as the equivalent of a std::vector + a std::forward\_list. Both implementations
allocate an 8-entry hash table (containing iterators into the list) on
initialization, and grow to 64 entries once 8 items are inserted. Above 64
items, the size doubles every time the load factor exceeds 1.

The empty size is sizeof(std::unordered\_map) = 64 +
the initial hash table size which is 8 pointers. The per-item overhead in the
table above counts the list node (2 pointers on Windows, 1 pointer in libc++),
plus amortizes the hash table assuming a 0.5 load factor on average.

In a microbenchmark on Windows, inserts of 1M integers into a
std::unordered\_set took 1.07x the time of std::set, and queries took 0.67x the
time of std::set. For a typical 4-entry set (the statistical mode of map sizes
in the browser), query performance is identical to std::set and base::flat\_set.
On ARM, unordered\_set performance can be worse because integer division to
compute the bucket is slow, and a few "less than" operations can be faster than
computing a hash depending on the key type. The takeaway is that you should not
default to using unordered maps because "they're faster."

### base::flat\_map and base::flat\_set

A sorted std::vector. Seached via binary search, inserts in the middle require
moving elements to make room. Good cache locality. For large objects and large
set sizes, std::vector's doubling-when-full strategy can waste memory.

Supports efficient construction from a vector of items which avoids the O(n^2)
insertion time of each element separately.

The per-item overhead will depend on the underlying std::vector's reallocation
strategy and the memory access pattern. Assuming items are being linearly added,
one would expect it to be 3/4 full, so per-item overhead will be 0.25 *
sizeof(T).


flat\_set/flat\_map support a notion of transparent comparisons. Therefore you
can, for example, lookup base::StringPiece in a set of std::strings without
constructing a temporary std::string. This functionality is based on C++14
extensions to std::set/std::map interface.

You can find more information about transparent comparisons here:
http://en.cppreference.com/w/cpp/utility/functional/less_void

Example, smart pointer set:

```cpp
// Define a custom comparator.
struct UniquePtrComparator {
  // Mark your comparison as transparent.
  using is_transparent = int;

  template <typename T>
  bool operator()(const std::unique_ptr<T>& lhs,
                  const std::unique_ptr<T>& rhs) const {
    return lhs < rhs;
  }

  template <typename T>
  bool operator()(const T* lhs, const std::unique_ptr<T>& rhs) const {
    return lhs < rhs.get();
  }

  template <typename T>
  bool operator()(const std::unique_ptr<T>& lhs, const T* rhs) const {
    return lhs.get() < rhs;
  }
};

// Declare a typedef.
template <typename T>
using UniquePtrSet = base::flat_set<std::unique_ptr<T>, UniquePtrComparator>;

// ...
// Collect data.
std::vector<std::unique_ptr<int>> ptr_vec;
ptr_vec.reserve(5);
std::generate_n(std::back_inserter(ptr_vec), 5, []{
  return base::MakeUnique<int>(0);
});

// Construct a set.
UniquePtrSet<int> ptr_set(std::move(ptr_vec), base::KEEP_FIRST_OF_DUPES);

// Use raw pointers to lookup keys.
int* ptr = ptr_set.begin()->get();
EXPECT_TRUE(ptr_set.find(ptr) == ptr_set.begin());
```

Example flat_map<std\::string, int>:

```cpp
base::flat_map<std::string, int> str_to_int({{"a", 1}, {"c", 2},{"b", 2}},
                                            base::KEEP_FIRST_OF_DUPES);

// Does not construct temporary strings.
str_to_int.find("c")->second = 3;
str_to_int.erase("c");
EXPECT_EQ(str_to_int.end(), str_to_int.find("c")->second);

// NOTE: This does construct a temporary string. This happens since if the
// item is not in the container, then it needs to be constructed, which is
// something that transparent comparators don't have to guarantee.
str_to_int["c"] = 3;
```

### base::small\_map

A small inline buffer that is brute-force searched that overflows into a full
std::map or std::unordered\_map. This gives the memory benefit of
base::flat\_map for small data sizes without the degenerate insertion
performance for large container sizes.

Since instantiations require both code for a std::map and a brute-force search
of the inline container, plus a fancy iterator to cover both cases, code size
is larger.

The initial size in the above table is assuming a very small inline table. The
actual size will be sizeof(int) + min(sizeof(std::map), sizeof(T) *
inline\_size).

## Appendix

### Code for map code size comparison

This just calls insert and query a number of times, with printfs that prevent
things from being dead-code eliminated.

```
TEST(Foo, Bar) {
  base::small_map<std::map<std::string, Flubber>> foo;
  foo.insert(std::make_pair("foo", Flubber(8, "bar")));
  foo.insert(std::make_pair("bar", Flubber(8, "bar")));
  foo.insert(std::make_pair("foo1", Flubber(8, "bar")));
  foo.insert(std::make_pair("bar1", Flubber(8, "bar")));
  foo.insert(std::make_pair("foo", Flubber(8, "bar")));
  foo.insert(std::make_pair("bar", Flubber(8, "bar")));
  auto found = foo.find("asdf");
  printf("Found is %d\n", (int)(found == foo.end()));
  found = foo.find("foo");
  printf("Found is %d\n", (int)(found == foo.end()));
  found = foo.find("bar");
  printf("Found is %d\n", (int)(found == foo.end()));
  found = foo.find("asdfhf");
  printf("Found is %d\n", (int)(found == foo.end()));
  found = foo.find("bar1");
  printf("Found is %d\n", (int)(found == foo.end()));
}
```


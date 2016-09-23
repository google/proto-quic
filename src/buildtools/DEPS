recursion = 1
use_relative_paths = True

vars = {
  "git_url": "https://chromium.googlesource.com",

  "clang_format_rev": "a72164df8be7d1c68ae1ad6c3541e7819200327e",   # r258328
  "libcxx_revision": "b1ece9c037d879843b0b0f5a2802e1e9d443b75a",    # r256621
  "libcxxabi_revision": "0edb61e2e581758fc4cd4cd09fc588b3fc91a653", # r256323
}

deps = {
  "clang_format/script":
      Var("git_url") + "/chromium/llvm-project/cfe/tools/clang-format.git@" +
      Var("clang_format_rev"),
  "third_party/libc++/trunk":
      Var("git_url") + "/chromium/llvm-project/libcxx.git" + "@" +
      Var("libcxx_revision"),
  "third_party/libc++abi/trunk":
      Var("git_url") + "/chromium/llvm-project/libcxxabi.git" + "@" +
      Var("libcxxabi_revision"),
}

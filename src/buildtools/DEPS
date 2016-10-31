use_relative_paths = True

vars = {
  "chromium_url": "https://chromium.googlesource.com",

  "clang_format_rev": "6a413e91d56d6fd0a6ff2f97c905c6dc5ca5d789", # r284988
  "libcxx_revision": "b1ece9c037d879843b0b0f5a2802e1e9d443b75a",    # r256621
  "libcxxabi_revision": "0edb61e2e581758fc4cd4cd09fc588b3fc91a653", # r256323
}

deps = {
  "clang_format/script":
    Var("chromium_url") + "/chromium/llvm-project/cfe/tools/clang-format.git@" +
    Var("clang_format_rev"),
  "third_party/libc++/trunk":
    Var("chromium_url") + "/chromium/llvm-project/libcxx.git" + "@" +
    Var("libcxx_revision"),
  "third_party/libc++abi/trunk":
    Var("chromium_url") + "/chromium/llvm-project/libcxxabi.git" + "@" +
    Var("libcxxabi_revision"),
}

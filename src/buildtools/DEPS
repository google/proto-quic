use_relative_paths = True

vars = {
  "chromium_url": "https://chromium.googlesource.com",

  "clang_format_rev": "0653eee0c81ea04715c635dd0885e8096ff6ba6d",   # r302580
  "libcxx_revision": "3a07dd740be63878167a0ea19fe81869954badd7",    # r303878
  "libcxxabi_revision": "4072e8fd76febee37f60aeda76d6d9f5e3791daa", # r303806
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

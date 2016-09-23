// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Handles various rewrites for base::ListValue::Append().

#ifndef TOOLS_CLANG_VALUE_CLEANUP_LIST_VALUE_REWRITER_H_
#define TOOLS_CLANG_VALUE_CLEANUP_LIST_VALUE_REWRITER_H_

#include <memory>
#include <unordered_set>

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Tooling/Refactoring.h"

class ListValueRewriter {
 public:
  explicit ListValueRewriter(clang::tooling::Replacements* replacements);

  void RegisterMatchers(clang::ast_matchers::MatchFinder* match_finder);

 private:
  class AppendCallback
      : public clang::ast_matchers::MatchFinder::MatchCallback {
   public:
    explicit AppendCallback(clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;

   protected:
    clang::tooling::Replacements* const replacements_;
  };

  class AppendBooleanCallback : public AppendCallback {
   public:
    explicit AppendBooleanCallback(clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendIntegerCallback : public AppendCallback {
   public:
    explicit AppendIntegerCallback(clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendDoubleCallback : public AppendCallback {
   public:
    explicit AppendDoubleCallback(clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendStringCallback : public AppendCallback {
   public:
    explicit AppendStringCallback(clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendReleasedUniquePtrCallback
      : public clang::ast_matchers::MatchFinder::MatchCallback {
   public:
    explicit AppendReleasedUniquePtrCallback(
        clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;

   private:
    clang::tooling::Replacements* const replacements_;
  };

  class AppendRawPtrCallback
      : public clang::ast_matchers::MatchFinder::MatchCallback {
   public:
    explicit AppendRawPtrCallback(clang::tooling::Replacements* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;

   private:
    clang::tooling::Replacements* const replacements_;
    std::unordered_set<const clang::VarDecl*> visited_;
  };

  AppendBooleanCallback append_boolean_callback_;
  AppendIntegerCallback append_integer_callback_;
  AppendDoubleCallback append_double_callback_;
  AppendStringCallback append_string_callback_;
  AppendReleasedUniquePtrCallback append_released_unique_ptr_callback_;
  AppendRawPtrCallback append_raw_ptr_callback_;
};

#endif  // TOOLS_CLANG_VALUE_CLEANUP_LIST_VALUE_REWRITER_H_

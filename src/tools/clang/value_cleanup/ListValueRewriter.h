// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Handles various rewrites for base::ListValue::Append().

#ifndef TOOLS_CLANG_VALUE_CLEANUP_LIST_VALUE_REWRITER_H_
#define TOOLS_CLANG_VALUE_CLEANUP_LIST_VALUE_REWRITER_H_

#include <memory>
#include <set>
#include <unordered_set>

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Tooling/Refactoring.h"

class ListValueRewriter {
 public:
  explicit ListValueRewriter(
      std::set<clang::tooling::Replacement>* replacements);

  void RegisterMatchers(clang::ast_matchers::MatchFinder* match_finder);

 private:
  class AppendCallback
      : public clang::ast_matchers::MatchFinder::MatchCallback {
   public:
    explicit AppendCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;

   protected:
    std::set<clang::tooling::Replacement>* const replacements_;
  };

  class AppendBooleanCallback : public AppendCallback {
   public:
    explicit AppendBooleanCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendIntegerCallback : public AppendCallback {
   public:
    explicit AppendIntegerCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendDoubleCallback : public AppendCallback {
   public:
    explicit AppendDoubleCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendStringCallback : public AppendCallback {
   public:
    explicit AppendStringCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;
  };

  class AppendReleasedUniquePtrCallback
      : public clang::ast_matchers::MatchFinder::MatchCallback {
   public:
    explicit AppendReleasedUniquePtrCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;

   private:
    std::set<clang::tooling::Replacement>* const replacements_;
  };

  class AppendRawPtrCallback
      : public clang::ast_matchers::MatchFinder::MatchCallback {
   public:
    explicit AppendRawPtrCallback(
        std::set<clang::tooling::Replacement>* replacements);

    void run(
        const clang::ast_matchers::MatchFinder::MatchResult& result) override;

   private:
    std::set<clang::tooling::Replacement>* const replacements_;
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

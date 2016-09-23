// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file containts a clang tool to update base::Bind() callers:
//  * Remove unneeded scoped_refptr<>::get() on method binding.

#include <assert.h>
#include <algorithm>
#include <memory>
#include <string>

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/TargetSelect.h"

using namespace clang::ast_matchers;
using clang::tooling::CommonOptionsParser;
using Replacements = std::vector<clang::tooling::Replacement>;

namespace {

// Remove unneeded scoped_refptr<>::get on a receivers of method bind.
// Example:
//   // Before
//   scoped_refptr<Foo> foo;
//   base::Bind(&Foo::Bar, foo.get());
//
//   // After
//   scoped_refptr<Foo> foo;
//   base::Bind(&Foo::Bar, foo);
//
class ScopedRefptrGetRewriter : public MatchFinder::MatchCallback {
 public:
  explicit ScopedRefptrGetRewriter(Replacements* replacements)
      : replacements_(replacements) {}

  StatementMatcher GetMatcher() {
    auto is_bind_call = callee(namedDecl(hasName("::base::Bind")));
    auto is_method_bind = hasArgument(0, hasType(memberPointerType()));
    auto is_raw_pointer_receiver = hasArgument(1, hasType(pointerType()));
    auto is_scoped_refptr_get_call =
        cxxMemberCallExpr(thisPointerType(namedDecl(hasName("scoped_refptr"))),
                          callee(namedDecl(hasName("get"))));
    return callExpr(is_bind_call, is_method_bind, is_raw_pointer_receiver,
                    hasArgument(1, is_scoped_refptr_get_call),
                    hasArgument(1, stmt().bind("target")));
  }

  void run(const MatchFinder::MatchResult& result) override {
    auto* target = result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("target");
    auto* member = llvm::cast<clang::MemberExpr>(target->getCallee());
    assert(target && member && "Unexpected match! No Expr captured!");
    auto range = clang::CharSourceRange::getTokenRange(
        result.SourceManager->getSpellingLoc(member->getOperatorLoc()),
        result.SourceManager->getSpellingLoc(target->getLocEnd()));

    replacements_->emplace_back(*result.SourceManager, range, "");
  }

 private:
  Replacements* replacements_;
};

llvm::cl::extrahelp common_help(CommonOptionsParser::HelpMessage);

}  // namespace.

int main(int argc, const char* argv[]) {
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmParser();
  llvm::cl::OptionCategory category(
      "Remove raw pointer on the receiver of Bind() target");
  CommonOptionsParser options(argc, argv, category);
  clang::tooling::ClangTool tool(options.getCompilations(),
                                 options.getSourcePathList());

  MatchFinder match_finder;
  std::vector<clang::tooling::Replacement> replacements;


  ScopedRefptrGetRewriter scoped_refptr_rewriter(&replacements);
  match_finder.addMatcher(scoped_refptr_rewriter.GetMatcher(),
                          &scoped_refptr_rewriter);

  std::unique_ptr<clang::tooling::FrontendActionFactory> factory =
      clang::tooling::newFrontendActionFactory(&match_finder);
  int result = tool.run(factory.get());
  if (result != 0)
    return result;

  // Serialization format is documented in tools/clang/scripts/run_tool.py
  llvm::outs() << "==== BEGIN EDITS ====\n";
  for (const auto& r : replacements) {
    std::string replacement_text = r.getReplacementText().str();
    std::replace(replacement_text.begin(), replacement_text.end(), '\n', '\0');
    llvm::outs() << "r:::" << r.getFilePath() << ":::" << r.getOffset()
                 << ":::" << r.getLength() << ":::" << replacement_text << "\n";
  }
  llvm::outs() << "==== END EDITS ====\n";

  return 0;
}

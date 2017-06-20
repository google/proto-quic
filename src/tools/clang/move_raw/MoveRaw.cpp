// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Clang tool to find where std::move is called on a raw pointer.
// Calling std::move on a raw pointer has no useful effect and is likely a
// sign of an error (e.g., mistaking a raw pointer for a smart pointer).
// TODO(crbug.com/731577): Make this a clang-tidy check instead.

#include <memory>
#include <set>
#include <string>

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"
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

namespace {

class MoveCallCollector : public MatchFinder::MatchCallback {
 public:
  explicit MoveCallCollector(
      std::set<clang::tooling::Replacement>* replacements)
      : replacements_(replacements) {}
  virtual void run(const MatchFinder::MatchResult& result) override;

 private:
  std::set<clang::tooling::Replacement>* const replacements_;
};

void MoveCallCollector::run(const MatchFinder::MatchResult& result) {
  const clang::Expr* callsite =
      result.Nodes.getNodeAs<clang::Expr>("move_call");
  replacements_->insert(clang::tooling::Replacement(
      *result.SourceManager,
      result.SourceManager->getSpellingLoc(callsite->getLocStart()), 0,
      "/*This tries to move a raw pointer!*/"));
}

}  // namespace

static llvm::cl::extrahelp common_help(CommonOptionsParser::HelpMessage);

int main(int argc, const char* argv[]) {
  // TODO(dcheng): Clang tooling should do this itself.
  // https://llvm.org/bugs/show_bug.cgi?id=21627
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmParser();
  llvm::cl::OptionCategory category(
      "Catching red flags: calling std::move on raw pointers");
  CommonOptionsParser options(argc, argv, category);
  clang::tooling::ClangTool tool(options.getCompilations(),
                                 options.getSourcePathList());

  MatchFinder match_finder;
  std::set<clang::tooling::Replacement> replacements;

  StatementMatcher move_on_raw_matcher =
      callExpr(argumentCountIs(1), callee(functionDecl(hasName("::std::move"))),
               hasArgument(0, hasType(pointerType())))
          .bind("move_call");
  MoveCallCollector callback(&replacements);
  match_finder.addMatcher(move_on_raw_matcher, &callback);

  std::unique_ptr<clang::tooling::FrontendActionFactory> factory =
      clang::tooling::newFrontendActionFactory(&match_finder);
  int result = tool.run(factory.get());
  if (result != 0)
    return result;

  if (replacements.empty())
    return 0;

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

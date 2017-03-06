// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ListValueRewriter.h"

#include <assert.h>
#include <algorithm>

#include "clang/AST/ASTContext.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/Refactoring.h"
#include "llvm/ADT/STLExtras.h"

using namespace clang::ast_matchers;
using clang::tooling::Replacement;
using llvm::StringRef;

namespace {

// Helper class for AppendRawCallback to visit each DeclRefExpr for a given
// VarDecl. If it finds a DeclRefExpr it can't figure out how to rewrite, the
// traversal will be terminated early.
class CollectDeclRefExprVisitor
    : public clang::RecursiveASTVisitor<CollectDeclRefExprVisitor> {
 public:
  CollectDeclRefExprVisitor(clang::SourceManager* source_manager,
                            clang::ASTContext* ast_context,
                            const clang::VarDecl* decl,
                            const clang::FunctionDecl* containing_function)
      : source_manager_(source_manager),
        ast_context_(ast_context),
        decl_(decl),
        is_valid_(decl->hasInit()),
        map_(containing_function->getBody()) {}

  // RecursiveASTVisitor:
  bool VisitDeclRefExpr(const clang::DeclRefExpr* expr) {
    if (expr->getDecl() != decl_)
      return true;

    const clang::Stmt* stmt = expr;
    while (stmt) {
      // TODO(dcheng): Add a const version of getParentIgnoreParenImpCasts.
      stmt = map_.getParentIgnoreParenImpCasts(const_cast<clang::Stmt*>(stmt));

      if (clang::isa<clang::MemberExpr>(stmt)) {
        // Member expressions need no special rewriting since std::unique_ptr
        // overloads `.' and `->'.
        return is_valid_;
      } else if (auto* member_call_expr =
                     clang::dyn_cast<clang::CXXMemberCallExpr>(stmt)) {
        return HandleMemberCallExpr(member_call_expr, expr);
      } else if (auto* binary_op =
                     clang::dyn_cast<clang::BinaryOperator>(stmt)) {
        return HandleBinaryOp(binary_op);
      } else {
        // Can't handle this so cancel the rewrite.
        stmt->dump();
        return false;
      }
    }

    assert(false);
    return false;
  }

  const std::set<clang::tooling::Replacement>& replacements() const {
    return replacements_;
  }

 private:
  bool HandleMemberCallExpr(const clang::CXXMemberCallExpr* member_call_expr,
                            const clang::DeclRefExpr* decl_ref_expr) {
    // If this isn't a ListValue::Append() call, cancel the rewrite: it
    // will require manual inspection to determine if it's an ownership
    // transferring call or not.
    auto* method_decl = member_call_expr->getMethodDecl();
    if (method_decl->getQualifiedNameAsString() != "base::ListValue::Append")
      return false;
    // Use-after-move is also a fatal error.
    if (!is_valid_)
      return false;

    is_valid_ = false;

    // Surround the DeclRefExpr with std::move().
    replacements_.emplace(*source_manager_, decl_ref_expr->getLocStart(), 0,
                          "std::move(");

    clang::SourceLocation end = clang::Lexer::getLocForEndOfToken(
        decl_ref_expr->getLocEnd(), 0, *source_manager_,
        ast_context_->getLangOpts());
    replacements_.emplace(*source_manager_, end, 0, ")");
    return true;
  }

  bool HandleBinaryOp(const clang::BinaryOperator* op) {
    if (op->isRelationalOp() || op->isEqualityOp() || op->isLogicalOp()) {
      // Supported binary operations for which no rewrites need to be done.
      return is_valid_;
    }
    if (!op->isAssignmentOp()) {
      // Pointer arithmetic or something else clever. Just cancel the rewrite.
      return false;
    }
    if (op->isCompoundAssignmentOp()) {
      // +=, -=, etc. Give up and cancel the rewrite.
      return false;
    }

    const clang::Expr* rhs = op->getRHS()->IgnoreParenImpCasts();
    const clang::CXXNewExpr* new_expr = clang::dyn_cast<clang::CXXNewExpr>(rhs);
    if (!new_expr) {
      // The variable isn't being assigned the result of a new operation. Just
      // cancel the rewrite.
      return false;
    }

    is_valid_ = true;

    // Rewrite the assignment operation to use std::unique_ptr::reset().
    clang::CharSourceRange range = clang::CharSourceRange::getCharRange(
        op->getOperatorLoc(), op->getRHS()->getLocStart());
    replacements_.emplace(*source_manager_, range, ".reset(");

    clang::SourceLocation expr_end = clang::Lexer::getLocForEndOfToken(
        op->getLocEnd(), 0, *source_manager_, ast_context_->getLangOpts());
    replacements_.emplace(*source_manager_, expr_end, 0, ")");
    return true;
  }

  clang::SourceManager* const source_manager_;
  clang::ASTContext* const ast_context_;
  const clang::VarDecl* const decl_;
  // Tracks the state of |decl_| during the traversal. |decl_| becomes valid
  // upon initialization/assignment and becomes invalid when passed as an
  // argument to base::ListValue::Append(base::Value*).
  bool is_valid_;
  clang::ParentMap map_;
  std::set<clang::tooling::Replacement> replacements_;
};

}  // namespace

ListValueRewriter::AppendCallback::AppendCallback(
    std::set<clang::tooling::Replacement>* replacements)
    : replacements_(replacements) {}

void ListValueRewriter::AppendCallback::run(
    const MatchFinder::MatchResult& result) {
  // Delete `new base::*Value(' and `)'.
  auto* newExpr = result.Nodes.getNodeAs<clang::CXXNewExpr>("newExpr");
  auto* argExpr = result.Nodes.getNodeAs<clang::Expr>("argExpr");

  // Note that for the end loc, we use the expansion loc: the argument might be
  // a macro like true and false.
  clang::CharSourceRange pre_arg_range = clang::CharSourceRange::getCharRange(
      newExpr->getLocStart(),
      result.SourceManager->getExpansionLoc(argExpr->getLocStart()));
  replacements_->emplace(*result.SourceManager, pre_arg_range, "");

  clang::CharSourceRange post_arg_range =
      clang::CharSourceRange::getTokenRange(newExpr->getLocEnd());
  replacements_->emplace(*result.SourceManager, post_arg_range, "");
}

ListValueRewriter::AppendBooleanCallback::AppendBooleanCallback(
    std::set<clang::tooling::Replacement>* replacements)
    : AppendCallback(replacements) {}

void ListValueRewriter::AppendBooleanCallback::run(
    const MatchFinder::MatchResult& result) {
  // Replace 'Append' with 'AppendBoolean'.
  auto* callExpr = result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("callExpr");

  clang::CharSourceRange call_range =
      clang::CharSourceRange::getTokenRange(callExpr->getExprLoc());
  replacements_->emplace(*result.SourceManager, call_range, "AppendBoolean");

  AppendCallback::run(result);
}

ListValueRewriter::AppendIntegerCallback::AppendIntegerCallback(
    std::set<clang::tooling::Replacement>* replacements)
    : AppendCallback(replacements) {}

void ListValueRewriter::AppendIntegerCallback::run(
    const MatchFinder::MatchResult& result) {
  // Replace 'Append' with 'AppendInteger'.
  auto* callExpr = result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("callExpr");

  clang::CharSourceRange call_range =
      clang::CharSourceRange::getTokenRange(callExpr->getExprLoc());
  replacements_->emplace(*result.SourceManager, call_range, "AppendInteger");

  AppendCallback::run(result);
}

ListValueRewriter::AppendDoubleCallback::AppendDoubleCallback(
    std::set<clang::tooling::Replacement>* replacements)
    : AppendCallback(replacements) {}

void ListValueRewriter::AppendDoubleCallback::run(
    const MatchFinder::MatchResult& result) {
  // Replace 'Append' with 'AppendDouble'.
  auto* callExpr = result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("callExpr");

  clang::CharSourceRange call_range =
      clang::CharSourceRange::getTokenRange(callExpr->getExprLoc());
  replacements_->emplace(*result.SourceManager, call_range, "AppendDouble");

  AppendCallback::run(result);
}

ListValueRewriter::AppendStringCallback::AppendStringCallback(
    std::set<clang::tooling::Replacement>* replacements)
    : AppendCallback(replacements) {}

void ListValueRewriter::AppendStringCallback::run(
    const MatchFinder::MatchResult& result) {
  // Replace 'Append' with 'AppendString'.
  auto* callExpr = result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("callExpr");

  clang::CharSourceRange call_range =
      clang::CharSourceRange::getTokenRange(callExpr->getExprLoc());
  replacements_->emplace(*result.SourceManager, call_range, "AppendString");

  AppendCallback::run(result);
}

ListValueRewriter::AppendReleasedUniquePtrCallback::
    AppendReleasedUniquePtrCallback(
        std::set<clang::tooling::Replacement>* replacements)
    : replacements_(replacements) {}

void ListValueRewriter::AppendReleasedUniquePtrCallback::run(
    const MatchFinder::MatchResult& result) {
  auto* object_expr = result.Nodes.getNodeAs<clang::Expr>("objectExpr");
  bool arg_is_rvalue = object_expr->Classify(*result.Context).isRValue();

  // Remove .release()
  auto* member_call =
      result.Nodes.getNodeAs<clang::CXXMemberCallExpr>("memberCall");
  auto* member_expr = result.Nodes.getNodeAs<clang::MemberExpr>("memberExpr");
  clang::CharSourceRange release_range = clang::CharSourceRange::getTokenRange(
      member_expr->getOperatorLoc(), member_call->getLocEnd());
  replacements_->emplace(*result.SourceManager, release_range,
                         arg_is_rvalue ? "" : ")");

  if (arg_is_rvalue)
    return;

  // Insert `std::move(' for non-rvalue expressions.
  clang::CharSourceRange insertion_range = clang::CharSourceRange::getCharRange(
      object_expr->getLocStart(), object_expr->getLocStart());
  replacements_->emplace(*result.SourceManager, insertion_range, "std::move(");
}

ListValueRewriter::AppendRawPtrCallback::AppendRawPtrCallback(
    std::set<clang::tooling::Replacement>* replacements)
    : replacements_(replacements) {}

void ListValueRewriter::AppendRawPtrCallback::run(
    const MatchFinder::MatchResult& result) {
  auto* var_decl = result.Nodes.getNodeAs<clang::VarDecl>("varDecl");
  // As an optimization, skip processing if it's already been visited, since
  // this match callback walks the entire function body.
  if (visited_.find(var_decl) != visited_.end())
    return;
  visited_.insert(var_decl);
  auto* function_context = var_decl->getParentFunctionOrMethod();
  assert(function_context && "local var not in function context?!");
  auto* function_decl = clang::cast<clang::FunctionDecl>(function_context);

  auto* type_source_info = var_decl->getTypeSourceInfo();
  assert(type_source_info && "no type source info for VarDecl?!");
  // Don't bother trying to handle qualifiers.
  clang::QualType qual_type = var_decl->getType();
  if (qual_type.hasQualifiers()) {
    return;
  }

  CollectDeclRefExprVisitor visitor(result.SourceManager, result.Context,
                                    var_decl, function_decl);
  if (!visitor.TraverseStmt(function_decl->getBody()))
    return;

  // Rewrite the variable type to use std::unique_ptr.
  clang::CharSourceRange type_range = clang::CharSourceRange::getTokenRange(
      type_source_info->getTypeLoc().getSourceRange());
  std::string replacement_type = "std::unique_ptr<";
  while (true) {
    const clang::Type* type = qual_type.getTypePtr();
    if (auto* auto_type = type->getAs<clang::AutoType>()) {
      if (!auto_type->isDeduced()) {
        // If an AutoType isn't deduced, the rewriter can't do anything.
        return;
      }
      qual_type = auto_type->getDeducedType();
    } else if (auto* pointer_type = type->getAs<clang::PointerType>()) {
      qual_type = pointer_type->getPointeeType();
    } else {
      break;
    }
  }
  replacement_type += qual_type.getAsString();
  replacement_type += ">";
  replacements_->emplace(*result.SourceManager, type_range, replacement_type);

  // Initialized with `='
  if (var_decl->hasInit() &&
      var_decl->getInitStyle() == clang::VarDecl::CInit) {
    clang::SourceLocation name_end = clang::Lexer::getLocForEndOfToken(
        var_decl->getLocation(), 0, *result.SourceManager,
        result.Context->getLangOpts());
    clang::CharSourceRange range = clang::CharSourceRange::getCharRange(
        name_end, var_decl->getInit()->getLocStart());
    replacements_->emplace(*result.SourceManager, range, "(");

    clang::SourceLocation init_end = clang::Lexer::getLocForEndOfToken(
        var_decl->getInit()->getLocEnd(), 0, *result.SourceManager,
        result.Context->getLangOpts());
    replacements_->emplace(*result.SourceManager, init_end, 0, ")");
  }

  // Also append the collected replacements from visiting the DeclRefExprs.
  replacements_->insert(visitor.replacements().begin(),
                        visitor.replacements().end());
}

ListValueRewriter::ListValueRewriter(
    std::set<clang::tooling::Replacement>* replacements)
    : append_boolean_callback_(replacements),
      append_integer_callback_(replacements),
      append_double_callback_(replacements),
      append_string_callback_(replacements),
      append_released_unique_ptr_callback_(replacements),
      append_raw_ptr_callback_(replacements) {}

void ListValueRewriter::RegisterMatchers(MatchFinder* match_finder) {
  auto is_list_append = cxxMemberCallExpr(
      callee(cxxMethodDecl(hasName("::base::ListValue::Append"))),
      argumentCountIs(1));

  // base::ListValue::Append(new base::Value(bool))
  //     => base::ListValue::AppendBoolean()
  match_finder->addMatcher(
      id("callExpr",
         cxxMemberCallExpr(
             is_list_append,
             hasArgument(
                 0, ignoringParenImpCasts(
                        id("newExpr",
                           cxxNewExpr(has(cxxConstructExpr(
                               hasDeclaration(cxxMethodDecl(
                                   hasName("::base::Value::FundamentalValue"))),
                               argumentCountIs(1),
                               hasArgument(
                                   0, id("argExpr",
                                         expr(hasType(booleanType())))))))))))),
      &append_boolean_callback_);

  // base::ListValue::Append(new base::Value(int))
  //     => base::ListValue::AppendInteger()
  match_finder->addMatcher(
      id("callExpr",
         cxxMemberCallExpr(
             is_list_append,
             hasArgument(
                 0,
                 ignoringParenImpCasts(id(
                     "newExpr",
                     cxxNewExpr(has(cxxConstructExpr(
                         hasDeclaration(cxxMethodDecl(
                             hasName("::base::Value::FundamentalValue"))),
                         argumentCountIs(1),
                         hasArgument(0, id("argExpr",
                                           expr(hasType(isInteger()),
                                                unless(hasType(
                                                    booleanType()))))))))))))),
      &append_integer_callback_);

  // base::ListValue::Append(new base::Value(double))
  //     => base::ListValue::AppendDouble()
  match_finder->addMatcher(
      id("callExpr",
         cxxMemberCallExpr(
             is_list_append,
             hasArgument(
                 0, ignoringParenImpCasts(id(
                        "newExpr",
                        cxxNewExpr(has(cxxConstructExpr(
                            hasDeclaration(cxxMethodDecl(
                                hasName("::base::Value::FundamentalValue"))),
                            argumentCountIs(1),
                            hasArgument(
                                0, id("argExpr",
                                      expr(hasType(
                                          realFloatingPointType())))))))))))),
      &append_double_callback_);

  // base::ListValue::Append(new base::StringValue(...))
  //     => base::ListValue::AppendString()
  match_finder->addMatcher(
      id("callExpr",
         cxxMemberCallExpr(
             is_list_append,
             hasArgument(
                 0, ignoringParenImpCasts(id(
                        "newExpr",
                        cxxNewExpr(has(cxxConstructExpr(
                            hasDeclaration(cxxMethodDecl(
                                hasName("::base::StringValue::StringValue"))),
                            argumentCountIs(1),
                            hasArgument(0, id("argExpr", expr())))))))))),
      &append_string_callback_);

  auto is_unique_ptr_release =
      allOf(callee(cxxMethodDecl(
                hasName("release"),
                ofClass(cxxRecordDecl(hasName("::std::unique_ptr"))))),
            argumentCountIs(0));

  // base::ListValue::Append(ReturnsUniquePtr().release())
  //     => base::ListValue::Append(ReturnsUniquePtr())
  //   or
  // base::ListValue::Append(unique_ptr_var.release())
  //     => base::ListValue::Append(std::move(unique_ptr_var))
  match_finder->addMatcher(
      cxxMemberCallExpr(
          is_list_append,
          hasArgument(
              0, ignoringParenImpCasts(
                     id("memberCall",
                        cxxMemberCallExpr(has(id("memberExpr", memberExpr())),
                                          is_unique_ptr_release,
                                          on(id("objectExpr", expr()))))))),
      &append_released_unique_ptr_callback_);

  // Simple versions of the following pattern. Note the callback itself does
  // much of the filtering (to detect use-after-move, things that aren't
  // assigned the result of a new expression, etc).
  //
  // base::ListValue* this_list = new base::ListValue;
  // this_list->AppendInteger(1);
  // that_list->Append(this_list);
  //
  // will be rewritten to
  //
  // std::unique_ptr<base::ListValue> this_list(new base::ListValue);
  // this_list->AppendInteger(1);
  // that_list->Append(std::move(this_list);
  match_finder->addMatcher(
      cxxMemberCallExpr(
          is_list_append,
          hasArgument(
              0,
              ignoringParenImpCasts(id(
                  "declRefExpr",
                  declRefExpr(to(id(
                      "varDecl",
                      varDecl(
                          hasLocalStorage(),
                          anyOf(hasInitializer(
                                    // Note this won't match C++11 uniform
                                    // initialization syntax, since the
                                    // CXXNewExpr is wrapped in an
                                    // InitListExpr in that case.
                                    ignoringParenImpCasts(cxxNewExpr())),
                                unless(hasInitializer(expr()))),
                          unless(parmVarDecl()))))))))),
      &append_raw_ptr_callback_);
}

// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Changes Blink-style names to Chrome-style names. Currently transforms:
//   fields:
//     int m_operationCount => int operation_count_
//   variables (including parameters):
//     int mySuperVariable => int my_super_variable
//   constants:
//     const int maxThings => const int kMaxThings
//   free functions and methods:
//     void doThisThenThat() => void DoThisAndThat()

#include <assert.h>
#include <algorithm>
#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersMacros.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/TargetSelect.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/file.h>
#include <unistd.h>
#endif

using namespace clang::ast_matchers;
using clang::tooling::CommonOptionsParser;
using clang::tooling::Replacement;
using llvm::StringRef;

namespace {

const char kBlinkFieldPrefix[] = "m_";
const char kBlinkStaticMemberPrefix[] = "s_";
const char kGeneratedFileRegex[] = "^gen/|/gen/";

template <typename MatcherType, typename NodeType>
bool IsMatching(const MatcherType& matcher,
                const NodeType& node,
                clang::ASTContext& context) {
  return !match(matcher, node, context).empty();
}

const clang::ast_matchers::internal::
    VariadicDynCastAllOfMatcher<clang::Expr, clang::UnresolvedMemberExpr>
        unresolvedMemberExpr;

const clang::ast_matchers::internal::
    VariadicDynCastAllOfMatcher<clang::Expr, clang::DependentScopeDeclRefExpr>
        dependentScopeDeclRefExpr;

const clang::ast_matchers::internal::
    VariadicDynCastAllOfMatcher<clang::Expr, clang::CXXDependentScopeMemberExpr>
        cxxDependentScopeMemberExpr;

AST_MATCHER(clang::FunctionDecl, isOverloadedOperator) {
  return Node.isOverloadedOperator();
}

AST_MATCHER(clang::CXXMethodDecl, isInstanceMethod) {
  return Node.isInstance();
}

AST_MATCHER_P(clang::FunctionTemplateDecl,
              templatedDecl,
              clang::ast_matchers::internal::Matcher<clang::FunctionDecl>,
              InnerMatcher) {
  return InnerMatcher.matches(*Node.getTemplatedDecl(), Finder, Builder);
}

// If |InnerMatcher| matches |top|, then the returned matcher will match:
// - |top::function|
// - |top::Class::method|
// - |top::internal::Class::method|
AST_MATCHER_P(
    clang::NestedNameSpecifier,
    hasTopLevelPrefix,
    clang::ast_matchers::internal::Matcher<clang::NestedNameSpecifier>,
    InnerMatcher) {
  const clang::NestedNameSpecifier* NodeToMatch = &Node;
  while (NodeToMatch->getPrefix())
    NodeToMatch = NodeToMatch->getPrefix();
  return InnerMatcher.matches(*NodeToMatch, Finder, Builder);
}

// This will narrow CXXCtorInitializers down for both FieldDecls and
// IndirectFieldDecls (ie. anonymous unions and such). In both cases
// getAnyMember() will return a FieldDecl which we can match against.
AST_MATCHER_P(clang::CXXCtorInitializer,
              forAnyField,
              clang::ast_matchers::internal::Matcher<clang::FieldDecl>,
              InnerMatcher) {
  const clang::FieldDecl* NodeAsDecl = Node.getAnyMember();
  return (NodeAsDecl != nullptr &&
          InnerMatcher.matches(*NodeAsDecl, Finder, Builder));
}

// Matches if all the overloads in the lookup set match the provided matcher.
AST_MATCHER_P(clang::OverloadExpr,
              allOverloadsMatch,
              clang::ast_matchers::internal::Matcher<clang::NamedDecl>,
              InnerMatcher) {
  if (Node.getNumDecls() == 0)
    return false;

  for (clang::NamedDecl* decl : Node.decls()) {
    if (!InnerMatcher.matches(*decl, Finder, Builder))
      return false;
  }
  return true;
}

template <typename T>
bool MatchAllOverriddenMethods(
    const clang::CXXMethodDecl& decl,
    T&& inner_matcher,
    clang::ast_matchers::internal::ASTMatchFinder* finder,
    clang::ast_matchers::internal::BoundNodesTreeBuilder* builder) {
  bool override_matches = false;
  bool override_not_matches = false;

  for (auto it = decl.begin_overridden_methods();
       it != decl.end_overridden_methods(); ++it) {
    if (MatchAllOverriddenMethods(**it, inner_matcher, finder, builder))
      override_matches = true;
    else
      override_not_matches = true;
  }

  // If this fires we have a class overriding a method that matches, and a
  // method that does not match the inner matcher. In that case we will match
  // one ancestor method but not the other. If we rename one of the and not the
  // other it will break what this class overrides, disconnecting it from the
  // one we did not rename which creates a behaviour change. So assert and
  // demand the user to fix the code first (or add the method to our
  // blacklist T_T).
  if (override_matches || override_not_matches)
    assert(override_matches != override_not_matches);

  // If the method overrides something that doesn't match, so the method itself
  // doesn't match.
  if (override_not_matches)
    return false;
  // If the method overrides something that matches, so the method ifself
  // matches.
  if (override_matches)
    return true;

  return inner_matcher.matches(decl, finder, builder);
}

AST_MATCHER_P(clang::CXXMethodDecl,
              includeAllOverriddenMethods,
              clang::ast_matchers::internal::Matcher<clang::CXXMethodDecl>,
              InnerMatcher) {
  return MatchAllOverriddenMethods(Node, InnerMatcher, Finder, Builder);
}

// Matches |T::m| and/or |x->T::m| and/or |x->m| CXXDependentScopeMemberExpr
// if member |m| comes from a type that matches the InnerMatcher.
AST_MATCHER_P(clang::CXXDependentScopeMemberExpr,
              hasMemberFromType,
              clang::ast_matchers::internal::Matcher<clang::QualType>,
              InnerMatcher) {
  // Given |T::m| and/or |x->T::m| and/or |x->m| ...
  if (clang::NestedNameSpecifier* nestedNameSpecifier = Node.getQualifier()) {
    // ... if |T| is present, then InnerMatcher has to match |T|.
    clang::QualType qualType(nestedNameSpecifier->getAsType(), 0);
    return InnerMatcher.matches(qualType, Finder, Builder);
  } else {
    // ... if there is no |T|, then InnerMatcher has to match the type of |x|.
    clang::Expr* base_expr = Node.isImplicitAccess() ? nullptr : Node.getBase();
    return base_expr &&
           InnerMatcher.matches(base_expr->getType(), Finder, Builder);
  }
}

// Matches |const Class<T>&| QualType if InnerMatcher matches |Class<T>|.
AST_MATCHER_P(clang::QualType,
              hasBaseType,
              clang::ast_matchers::internal::Matcher<clang::Type>,
              InnerMatcher) {
  const clang::Type* type = Node.getTypePtrOrNull();
  return type && InnerMatcher.matches(*type, Finder, Builder);
}

bool IsMethodOverrideOf(const clang::CXXMethodDecl& decl,
                        const char* class_name) {
  if (decl.getParent()->getQualifiedNameAsString() == class_name)
    return true;
  for (auto it = decl.begin_overridden_methods();
       it != decl.end_overridden_methods(); ++it) {
    if (IsMethodOverrideOf(**it, class_name))
      return true;
  }
  return false;
}

bool IsBlacklistedFunction(const clang::FunctionDecl& decl) {
  // swap() functions should match the signature of std::swap for ADL tricks.
  return decl.getName() == "swap";
}

bool IsBlacklistedMethod(const clang::CXXMethodDecl& decl) {
  if (decl.isStatic())
    return false;

  clang::StringRef name = decl.getName();

  // These methods should never be renamed.
  static const char* kBlacklistMethods[] = {"trace", "traceImpl", "lock",
                                            "unlock", "try_lock"};
  for (const auto& b : kBlacklistMethods) {
    if (name == b)
      return true;
  }

  // Iterator methods shouldn't be renamed to work with stl and range-for
  // loops.
  std::string ret_type = decl.getReturnType().getAsString();
  if (ret_type.find("iterator") != std::string::npos ||
      ret_type.find("Iterator") != std::string::npos) {
    static const char* kIteratorBlacklist[] = {"begin", "end", "rbegin",
                                               "rend"};
    for (const auto& b : kIteratorBlacklist) {
      if (name == b)
        return true;
    }
  }

  // Subclasses of InspectorAgent will subclass "disable()" from both blink and
  // from gen/, which is problematic, but DevTools folks don't want to rename
  // it or split this up. So don't rename it at all.
  if (name.equals("disable") &&
      IsMethodOverrideOf(decl, "blink::InspectorAgent"))
    return true;

  return false;
}

bool IsBlacklistedFunctionOrMethodName(llvm::StringRef name) {
  static const char* kBlacklistedNames[] = {
      // From IsBlacklistedFunction:
      "swap",
      // From IsBlacklistedMethod:
      "trace", "traceImpl", "lock", "unlock", "try_lock", "begin", "end",
      "rbegin", "rend", "disable",
  };
  for (const auto& b : kBlacklistedNames) {
    if (name == b)
      return true;
  }
  return false;
}

AST_MATCHER(clang::FunctionDecl, isBlacklistedFunction) {
  return IsBlacklistedFunction(Node);
}

AST_MATCHER(clang::CXXMethodDecl, isBlacklistedMethod) {
  return IsBlacklistedMethod(Node);
}

// Helper to convert from a camelCaseName to camel_case_name. It uses some
// heuristics to try to handle acronyms in camel case names correctly.
std::string CamelCaseToUnderscoreCase(StringRef input) {
  std::string output;
  bool needs_underscore = false;
  bool was_lowercase = false;
  bool was_uppercase = false;
  bool first_char = true;
  // Iterate in reverse to minimize the amount of backtracking.
  for (const unsigned char* i = input.bytes_end() - 1; i >= input.bytes_begin();
       --i) {
    char c = *i;
    bool is_lowercase = clang::isLowercase(c);
    bool is_uppercase = clang::isUppercase(c);
    c = clang::toLowercase(c);
    // Transitioning from upper to lower case requires an underscore. This is
    // needed to handle names with acronyms, e.g. handledHTTPRequest needs a '_'
    // in 'dH'. This is a complement to the non-acronym case further down.
    if (was_uppercase && is_lowercase)
      needs_underscore = true;
    if (needs_underscore) {
      output += '_';
      needs_underscore = false;
    }
    output += c;
    // Handles the non-acronym case: transitioning from lower to upper case
    // requires an underscore when emitting the next character, e.g. didLoad
    // needs a '_' in 'dL'.
    if (!first_char && was_lowercase && is_uppercase)
      needs_underscore = true;
    was_lowercase = is_lowercase;
    was_uppercase = is_uppercase;
    first_char = false;
  }
  std::reverse(output.begin(), output.end());
  return output;
}

bool IsProbablyConst(const clang::VarDecl& decl,
                     const clang::ASTContext& context) {
  clang::QualType type = decl.getType();
  if (!type.isConstQualified())
    return false;

  if (type.isVolatileQualified())
    return false;

  // http://google.github.io/styleguide/cppguide.html#Constant_Names
  // Static variables that are const-qualified should use kConstantStyle naming.
  if (decl.getStorageDuration() == clang::SD_Static)
    return true;

  const clang::Expr* initializer = decl.getInit();
  if (!initializer)
    return false;

  // If the expression is dependent on a template input, then we are not
  // sure if it can be compile-time generated as calling isEvaluatable() is
  // not valid on |initializer|.
  // TODO(crbug.com/581218): We could probably look at each compiled
  // instantiation of the template and see if they are all compile-time
  // isEvaluable().
  if (initializer->isInstantiationDependent())
    return false;

  // If the expression can be evaluated at compile time, then it should have a
  // kFoo style name. Otherwise, not.
  return initializer->isEvaluatable(context);
}

AST_MATCHER_P(clang::QualType, hasString, std::string, ExpectedString) {
  return ExpectedString == Node.getAsString();
}

bool GetNameForDecl(const clang::FunctionDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  name = decl.getName().str();
  name[0] = clang::toUppercase(name[0]);

  // Given
  //   class Foo {};
  //   using Bar = Foo;
  //   Bar f1();  // <- |Bar| would be matched by hasString("Bar") below.
  //   Bar f2();  // <- |Bar| would be matched by hasName("Foo") below.
  // |type_with_same_name_as_function| matcher matches Bar and Foo return types.
  auto type_with_same_name_as_function = qualType(anyOf(
      hasString(name),  // hasString matches the type as spelled (Bar above).
      hasDeclaration(namedDecl(hasName(name)))));  // hasDeclaration matches
                                                   // resolved type (Foo above).
  // |type_containing_same_name_as_function| matcher will match all of the
  // return types below:
  // - Foo foo()  // Direct application of |type_with_same_name_as_function|.
  // - Foo* foo()  // |hasDescendant| traverses references/pointers.
  // - RefPtr<Foo> foo()  // |hasDescendant| traverses template arguments.
  auto type_containing_same_name_as_function =
      qualType(anyOf(type_with_same_name_as_function,
                     hasDescendant(type_with_same_name_as_function)));
  // https://crbug.com/582312: Prepend "Get" if method name conflicts with
  // return type.
  auto conflict_matcher =
      functionDecl(returns(type_containing_same_name_as_function));
  if (IsMatching(conflict_matcher, decl, context))
    name = "Get" + name;

  return true;
}

bool GetNameForDecl(const clang::EnumConstantDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  StringRef original_name = decl.getName();

  // If it's already correct leave it alone.
  if (original_name.size() >= 2 && original_name[0] == 'k' &&
      clang::isUppercase(original_name[1]))
    return false;

  bool is_shouty = true;
  for (char c : original_name) {
    if (!clang::isUppercase(c) && !clang::isDigit(c) && c != '_') {
      is_shouty = false;
      break;
    }
  }

  if (is_shouty)
    return false;

  name = 'k';  // k prefix on enum values.
  name += original_name;
  name[1] = clang::toUppercase(name[1]);
  return true;
}

bool GetNameForDecl(const clang::FieldDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  StringRef original_name = decl.getName();
  bool member_prefix = original_name.startswith(kBlinkFieldPrefix);

  StringRef rename_part = !member_prefix
                              ? original_name
                              : original_name.substr(strlen(kBlinkFieldPrefix));
  name = CamelCaseToUnderscoreCase(rename_part);

  // Assume that prefix of m_ was intentional and always replace it with a
  // suffix _.
  if (member_prefix && name.back() != '_')
    name += '_';

  return true;
}

bool GetNameForDecl(const clang::VarDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  StringRef original_name = decl.getName();

  // Nothing to do for unnamed parameters.
  if (clang::isa<clang::ParmVarDecl>(decl)) {
    if (original_name.empty())
      return false;

    // Check if |decl| and |decl.getLocation| are in sync.  We need to skip
    // out-of-sync ParmVarDecls to avoid renaming buggy ParmVarDecls that
    // 1) have decl.getLocation() pointing at a parameter declaration without a
    // name, but 2) have decl.getName() retained from a template specialization
    // of a method.  See also: https://llvm.org/bugs/show_bug.cgi?id=29145
    clang::SourceLocation loc =
        context.getSourceManager().getSpellingLoc(decl.getLocation());
    auto parents = context.getParents(decl);
    bool is_child_location_within_parent_source_range = std::all_of(
        parents.begin(), parents.end(),
        [&loc](const clang::ast_type_traits::DynTypedNode& parent) {
          clang::SourceLocation begin = parent.getSourceRange().getBegin();
          clang::SourceLocation end = parent.getSourceRange().getEnd();
          return (begin < loc) && (loc < end);
        });
    if (!is_child_location_within_parent_source_range)
      return false;
  }

  // static class members match against VarDecls. Blink style dictates that
  // these should be prefixed with `s_`, so strip that off. Also check for `m_`
  // and strip that off too, for code that accidentally uses the wrong prefix.
  if (original_name.startswith(kBlinkStaticMemberPrefix))
    original_name = original_name.substr(strlen(kBlinkStaticMemberPrefix));
  else if (original_name.startswith(kBlinkFieldPrefix))
    original_name = original_name.substr(strlen(kBlinkFieldPrefix));

  bool is_const = IsProbablyConst(decl, context);
  if (is_const) {
    // Don't try to rename constants that already conform to Chrome style.
    if (original_name.size() >= 2 && original_name[0] == 'k' &&
        clang::isUppercase(original_name[1]))
      return false;

    name = 'k';
    name.append(original_name.data(), original_name.size());
    name[1] = clang::toUppercase(name[1]);
  } else {
    name = CamelCaseToUnderscoreCase(original_name);

    // Non-const variables with static storage duration at namespace scope are
    // prefixed with `g_' to reduce the likelihood of a naming collision.
    const clang::DeclContext* decl_context = decl.getDeclContext();
    if (name.find("g_") != 0 && decl.hasGlobalStorage() &&
        decl_context->isNamespace())
      name.insert(0, "g_");
  }

  // Static members end with _ just like other members, but constants should
  // not.
  if (!is_const && decl.isStaticDataMember()) {
    name += '_';
  }

  return true;
}

bool GetNameForDecl(const clang::FunctionTemplateDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  clang::FunctionDecl* templated_function = decl.getTemplatedDecl();
  return GetNameForDecl(*templated_function, context, name);
}

bool GetNameForDecl(const clang::NamedDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  if (auto* function = clang::dyn_cast<clang::FunctionDecl>(&decl))
    return GetNameForDecl(*function, context, name);
  if (auto* var = clang::dyn_cast<clang::VarDecl>(&decl))
    return GetNameForDecl(*var, context, name);
  if (auto* field = clang::dyn_cast<clang::FieldDecl>(&decl))
    return GetNameForDecl(*field, context, name);
  if (auto* function_template =
          clang::dyn_cast<clang::FunctionTemplateDecl>(&decl))
    return GetNameForDecl(*function_template, context, name);
  if (auto* enumc = clang::dyn_cast<clang::EnumConstantDecl>(&decl))
    return GetNameForDecl(*enumc, context, name);

  return false;
}

bool GetNameForDecl(const clang::UsingDecl& decl,
                    clang::ASTContext& context,
                    std::string& name) {
  assert(decl.shadow_size() > 0);

  // If a using declaration's targeted declaration is a set of overloaded
  // functions, it can introduce multiple shadowed declarations. Just using the
  // first one is OK, since overloaded functions have the same name, by
  // definition.
  return GetNameForDecl(*decl.shadow_begin()->getTargetDecl(), context, name);
}

template <typename Type>
struct TargetNodeTraits;

template <>
struct TargetNodeTraits<clang::NamedDecl> {
  static clang::SourceLocation GetLoc(const clang::NamedDecl& decl) {
    return decl.getLocation();
  }
  static const char* GetName() { return "decl"; }
  static const char* GetType() { return "NamedDecl"; }
};

template <>
struct TargetNodeTraits<clang::MemberExpr> {
  static clang::SourceLocation GetLoc(const clang::MemberExpr& expr) {
    return expr.getMemberLoc();
  }
  static const char* GetName() { return "expr"; }
  static const char* GetType() { return "MemberExpr"; }
};

template <>
struct TargetNodeTraits<clang::DeclRefExpr> {
  static clang::SourceLocation GetLoc(const clang::DeclRefExpr& expr) {
    return expr.getLocation();
  }
  static const char* GetName() { return "expr"; }
  static const char* GetType() { return "DeclRefExpr"; }
};

template <>
struct TargetNodeTraits<clang::DependentScopeDeclRefExpr> {
  static clang::SourceLocation GetLoc(
      const clang::DependentScopeDeclRefExpr& expr) {
    return expr.getLocation();
  }
  static const char* GetName() { return "expr"; }
};

template <>
struct TargetNodeTraits<clang::CXXDependentScopeMemberExpr> {
  static clang::SourceLocation GetLoc(
      const clang::CXXDependentScopeMemberExpr& expr) {
    return expr.getMemberLoc();
  }
  static const char* GetName() { return "expr"; }
};

template <>
struct TargetNodeTraits<clang::CXXCtorInitializer> {
  static clang::SourceLocation GetLoc(const clang::CXXCtorInitializer& init) {
    assert(init.isWritten());
    return init.getSourceLocation();
  }
  static const char* GetName() { return "initializer"; }
  static const char* GetType() { return "CXXCtorInitializer"; }
};

template <>
struct TargetNodeTraits<clang::UnresolvedLookupExpr> {
  static clang::SourceLocation GetLoc(const clang::UnresolvedLookupExpr& expr) {
    return expr.getNameLoc();
  }
  static const char* GetName() { return "expr"; }
  static const char* GetType() { return "UnresolvedLookupExpr"; }
};

template <>
struct TargetNodeTraits<clang::UnresolvedMemberExpr> {
  static clang::SourceLocation GetLoc(const clang::UnresolvedMemberExpr& expr) {
    return expr.getMemberLoc();
  }
  static const char* GetName() { return "expr"; }
  static const char* GetType() { return "UnresolvedMemberExpr"; }
};

template <>
struct TargetNodeTraits<clang::UnresolvedUsingValueDecl> {
  static clang::SourceLocation GetLoc(
      const clang::UnresolvedUsingValueDecl& decl) {
    return decl.getNameInfo().getLoc();
  }
  static const char* GetName() { return "decl"; }
  static const char* GetType() { return "UnresolvedUsingValueDecl"; }
};

template <typename TargetNode>
class RewriterBase : public MatchFinder::MatchCallback {
 public:
  explicit RewriterBase(std::set<Replacement>* replacements)
      : replacements_(replacements) {}

  const TargetNode& GetTargetNode(const MatchFinder::MatchResult& result) {
    const TargetNode* target_node = result.Nodes.getNodeAs<TargetNode>(
        TargetNodeTraits<TargetNode>::GetName());
    assert(target_node);
    return *target_node;
  }

  void AddReplacement(const MatchFinder::MatchResult& result,
                      llvm::StringRef old_name,
                      std::string new_name) {
    if (old_name == new_name)
      return;

    clang::SourceLocation loc =
        TargetNodeTraits<TargetNode>::GetLoc(GetTargetNode(result));
    clang::CharSourceRange range = clang::CharSourceRange::getTokenRange(loc);
    replacements_->emplace(*result.SourceManager, range, new_name);
    replacement_names_.emplace(old_name.str(), std::move(new_name));
  }

  const std::unordered_map<std::string, std::string>& replacement_names()
      const {
    return replacement_names_;
  }

 private:
  std::set<Replacement>* const replacements_;
  std::unordered_map<std::string, std::string> replacement_names_;
};

template <typename DeclNode, typename TargetNode>
class DeclRewriterBase : public RewriterBase<TargetNode> {
 public:
  using Base = RewriterBase<TargetNode>;

  explicit DeclRewriterBase(std::set<Replacement>* replacements)
      : Base(replacements) {}

  void run(const MatchFinder::MatchResult& result) override {
    const DeclNode* decl = result.Nodes.getNodeAs<DeclNode>("decl");
    assert(decl);
    // If false, there's no name to be renamed.
    if (!decl->getIdentifier())
      return;
    clang::SourceLocation decl_loc =
        TargetNodeTraits<clang::NamedDecl>::GetLoc(*decl);
    if (decl_loc.isMacroID()) {
      // Get the location of the spelling of the declaration. If token pasting
      // was used this will be in "scratch space" and we don't know how to get
      // from there back to/ the actual macro with the foo##bar text. So just
      // don't replace in that case.
      clang::SourceLocation spell =
          result.SourceManager->getSpellingLoc(decl_loc);
      if (result.SourceManager->getBufferName(spell) == "<scratch space>")
        return;
    }
    clang::ASTContext* context = result.Context;
    std::string new_name;
    if (!GetNameForDecl(*decl, *context, new_name))
      return;  // If false, the name was not suitable for renaming.
    llvm::StringRef old_name = decl->getName();
    Base::AddReplacement(result, old_name, std::move(new_name));
  }
};

using FieldDeclRewriter = DeclRewriterBase<clang::FieldDecl, clang::NamedDecl>;
using VarDeclRewriter = DeclRewriterBase<clang::VarDecl, clang::NamedDecl>;
using MemberRewriter = DeclRewriterBase<clang::FieldDecl, clang::MemberExpr>;
using DeclRefRewriter = DeclRewriterBase<clang::VarDecl, clang::DeclRefExpr>;
using FieldDeclRefRewriter =
    DeclRewriterBase<clang::FieldDecl, clang::DeclRefExpr>;
using FunctionDeclRewriter =
    DeclRewriterBase<clang::FunctionDecl, clang::NamedDecl>;
using FunctionRefRewriter =
    DeclRewriterBase<clang::FunctionDecl, clang::DeclRefExpr>;
using ConstructorInitializerRewriter =
    DeclRewriterBase<clang::FieldDecl, clang::CXXCtorInitializer>;

using MethodDeclRewriter =
    DeclRewriterBase<clang::CXXMethodDecl, clang::NamedDecl>;
using MethodRefRewriter =
    DeclRewriterBase<clang::CXXMethodDecl, clang::DeclRefExpr>;
using MethodMemberRewriter =
    DeclRewriterBase<clang::CXXMethodDecl, clang::MemberExpr>;

using EnumConstantDeclRewriter =
    DeclRewriterBase<clang::EnumConstantDecl, clang::NamedDecl>;
using EnumConstantDeclRefRewriter =
    DeclRewriterBase<clang::EnumConstantDecl, clang::DeclRefExpr>;

using UnresolvedLookupRewriter =
    DeclRewriterBase<clang::NamedDecl, clang::UnresolvedLookupExpr>;
using UnresolvedMemberRewriter =
    DeclRewriterBase<clang::NamedDecl, clang::UnresolvedMemberExpr>;

using UsingDeclRewriter = DeclRewriterBase<clang::UsingDecl, clang::NamedDecl>;

clang::DeclarationName GetUnresolvedName(
    const clang::UnresolvedMemberExpr& expr) {
  return expr.getMemberName();
}

clang::DeclarationName GetUnresolvedName(
    const clang::DependentScopeDeclRefExpr& expr) {
  return expr.getDeclName();
}

clang::DeclarationName GetUnresolvedName(
    const clang::CXXDependentScopeMemberExpr& expr) {
  return expr.getMember();
}

clang::DeclarationName GetUnresolvedName(
    const clang::UnresolvedUsingValueDecl& decl) {
  return decl.getDeclName();
}

// Returns whether |expr_node| is used as a callee in the AST (i.e. if
// |expr_node| needs to resolve to a method or a function).
bool IsCallee(const clang::Expr& expr, clang::ASTContext& context) {
  auto matcher = stmt(hasParent(callExpr(callee(equalsNode(&expr)))));
  return IsMatching(matcher, expr, context);
}

// Returns whether |decl| will be used as a callee in the AST (i.e. if the value
// brought by the using declaration will resolve to a method or a function).
bool IsCallee(const clang::UnresolvedUsingValueDecl& decl,
              clang::ASTContext& /* context */) {
  // Caller (i.e. GuessNameForUnresolvedDependentNode) should have already
  // filtered out fields before calling |IsCallee|.
  clang::IdentifierInfo* info = GetUnresolvedName(decl).getAsIdentifierInfo();
  assert(info);
  bool name_looks_like_a_field = info->getName().startswith(kBlinkFieldPrefix);
  assert(!name_looks_like_a_field);

  // Looking just at clang::UnresolvedUsingValueDecl, we cannot tell whether it
  // refers to something callable or not.  Since fields should have been already
  // filtered out before calling IsCallee (see the assert above), let's assume
  // that |using Base::foo| refers to a method.
  return true;
}

template <typename TargetNode>
class UnresolvedRewriterBase : public RewriterBase<TargetNode> {
 public:
  using Base = RewriterBase<TargetNode>;

  explicit UnresolvedRewriterBase(std::set<Replacement>* replacements)
      : RewriterBase<TargetNode>(replacements) {}

  void run(const MatchFinder::MatchResult& result) override {
    const TargetNode& node = Base::GetTargetNode(result);

    clang::DeclarationName decl_name = GetUnresolvedName(node);
    switch (decl_name.getNameKind()) {
      // Do not rewrite this:
      //   return operator T*();
      // into this:
      //   return Operator type - parameter - 0 - 0 * T * ();
      case clang::DeclarationName::NameKind::CXXConversionFunctionName:
      case clang::DeclarationName::NameKind::CXXOperatorName:
      case clang::DeclarationName::NameKind::CXXLiteralOperatorName:
        return;
      default:
        break;
    }

    // Make sure there is an old name + extract the old name.
    clang::IdentifierInfo* info = GetUnresolvedName(node).getAsIdentifierInfo();
    if (!info)
      return;
    llvm::StringRef old_name = info->getName();

    // Try to guess a new name.
    std::string new_name;
    if (GuessNameForUnresolvedDependentNode(node, *result.Context, old_name,
                                            new_name))
      Base::AddReplacement(result, old_name, std::move(new_name));
  }

 private:
  // This method calculates a new name for nodes that depend on template
  // parameters (http://en.cppreference.com/w/cpp/language/dependent_name).  The
  // renaming is based on crude heuristics, because such nodes are not bound to
  // a specific decl until template instantiation - at the point of rename, one
  // cannot tell whether the node will eventually resolve to a field / method /
  // constant / etc.
  //
  // The method returns false if no renaming should be done.
  // Otherwise the method returns true and sets |new_name|.
  bool GuessNameForUnresolvedDependentNode(const TargetNode& node,
                                           clang::ASTContext& context,
                                           llvm::StringRef old_name,
                                           std::string& new_name) {
    // |m_fieldName| -> |field_name_|.
    if (old_name.startswith(kBlinkFieldPrefix)) {
      std::string field_name = old_name.substr(strlen(kBlinkFieldPrefix));
      if (field_name.find('_') == std::string::npos) {
        new_name = CamelCaseToUnderscoreCase(field_name) + "_";
        return true;
      }
    }

    // |T::myMethod(...)| -> |T::MyMethod(...)|.
    if ((old_name.find('_') == std::string::npos) && IsCallee(node, context) &&
        !IsBlacklistedFunctionOrMethodName(old_name)) {
      new_name = old_name;
      new_name[0] = clang::toUppercase(old_name[0]);
      return true;
    }

    // In the future we can consider more heuristics:
    // - "s_" and "g_" prefixes
    // - "ALL_CAPS"
    // - |T::myStaticField| -> |T::kMyStaticField|
    //   (but have to be careful not to rename |value| in WTF/TypeTraits.h?)
    return false;
  }
};

using UnresolvedDependentMemberRewriter =
    UnresolvedRewriterBase<clang::UnresolvedMemberExpr>;

using UnresolvedUsingValueDeclRewriter =
    UnresolvedRewriterBase<clang::UnresolvedUsingValueDecl>;

using DependentScopeDeclRefExprRewriter =
    UnresolvedRewriterBase<clang::DependentScopeDeclRefExpr>;

using CXXDependentScopeMemberExprRewriter =
    UnresolvedRewriterBase<clang::CXXDependentScopeMemberExpr>;

}  // namespace

static llvm::cl::extrahelp common_help(CommonOptionsParser::HelpMessage);

int main(int argc, const char* argv[]) {
  // TODO(dcheng): Clang tooling should do this itself.
  // http://llvm.org/bugs/show_bug.cgi?id=21627
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmParser();
  llvm::cl::OptionCategory category(
      "rewrite_to_chrome_style: convert Blink style to Chrome style.");
  CommonOptionsParser options(argc, argv, category);
  clang::tooling::ClangTool tool(options.getCompilations(),
                                 options.getSourcePathList());

  MatchFinder match_finder;
  std::set<Replacement> replacements;

  // Blink namespace matchers ========
  auto blink_namespace_decl =
      namespaceDecl(anyOf(hasName("blink"), hasName("WTF")),
                    hasParent(translationUnitDecl()));

  // Given top-level compilation unit:
  //   namespace WTF {
  //     void foo() {}
  //   }
  // matches |foo|.
  auto decl_under_blink_namespace = decl(hasAncestor(blink_namespace_decl));

  // Given top-level compilation unit:
  //   void WTF::function() {}
  //   void WTF::Class::method() {}
  // matches |WTF::function| and |WTF::Class::method| decls.
  auto decl_has_qualifier_to_blink_namespace =
      declaratorDecl(has(nestedNameSpecifier(
          hasTopLevelPrefix(specifiesNamespace(blink_namespace_decl)))));

  auto in_blink_namespace = decl(
      anyOf(decl_under_blink_namespace, decl_has_qualifier_to_blink_namespace,
            hasAncestor(decl_has_qualifier_to_blink_namespace)),
      unless(isExpansionInFileMatching(kGeneratedFileRegex)));

  // Field, variable, and enum declarations ========
  // Given
  //   int x;
  //   struct S {
  //     int y;
  //     enum { VALUE };
  //   };
  // matches |x|, |y|, and |VALUE|.
  auto field_decl_matcher = id("decl", fieldDecl(in_blink_namespace));
  auto is_type_trait_value =
      varDecl(hasName("value"), hasStaticStorageDuration(), isPublic(),
              hasType(isConstQualified()), hasType(type(anyOf(
                  booleanType(), enumType()))),
              unless(hasAncestor(recordDecl(
                  has(cxxMethodDecl(isUserProvided(), isInstanceMethod()))))));
  auto var_decl_matcher =
      id("decl", varDecl(in_blink_namespace, unless(is_type_trait_value)));
  auto enum_member_decl_matcher =
      id("decl", enumConstantDecl(in_blink_namespace));

  FieldDeclRewriter field_decl_rewriter(&replacements);
  match_finder.addMatcher(field_decl_matcher, &field_decl_rewriter);

  VarDeclRewriter var_decl_rewriter(&replacements);
  match_finder.addMatcher(var_decl_matcher, &var_decl_rewriter);

  EnumConstantDeclRewriter enum_member_decl_rewriter(&replacements);
  match_finder.addMatcher(enum_member_decl_matcher, &enum_member_decl_rewriter);

  // Field, variable, and enum references ========
  // Given
  //   bool x = true;
  //   if (x) {
  //     ...
  //   }
  // matches |x| in if (x).
  auto member_matcher = id(
      "expr",
      memberExpr(
          member(field_decl_matcher),
          // Needed to avoid matching member references in functions (which will
          // be an ancestor of the member reference) synthesized by the
          // compiler, such as a synthesized copy constructor.
          // This skips explicitly defaulted functions as well, but that's OK:
          // there's nothing interesting to rewrite in those either.
          unless(hasAncestor(functionDecl(isDefaulted())))));
  auto decl_ref_matcher = id("expr", declRefExpr(to(var_decl_matcher)));
  auto enum_member_ref_matcher =
      id("expr", declRefExpr(to(enum_member_decl_matcher)));

  MemberRewriter member_rewriter(&replacements);
  match_finder.addMatcher(member_matcher, &member_rewriter);

  DeclRefRewriter decl_ref_rewriter(&replacements);
  match_finder.addMatcher(decl_ref_matcher, &decl_ref_rewriter);

  EnumConstantDeclRefRewriter enum_member_ref_rewriter(&replacements);
  match_finder.addMatcher(enum_member_ref_matcher, &enum_member_ref_rewriter);

  // Member references in a non-member context ========
  // Given
  //   struct S {
  //     typedef int U::*UnspecifiedBoolType;
  //     operator UnspecifiedBoolType() { return s_ ? &U::s_ : 0; }
  //     int s_;
  //   };
  // matches |&U::s_| but not |s_|.
  auto member_ref_matcher = id("expr", declRefExpr(to(field_decl_matcher)));

  FieldDeclRefRewriter member_ref_rewriter(&replacements);
  match_finder.addMatcher(member_ref_matcher, &member_ref_rewriter);

  // Non-method function declarations ========
  // Given
  //   void f();
  //   struct S {
  //     void g();
  //   };
  // matches |f| but not |g|.
  auto function_decl_matcher = id(
      "decl",
      functionDecl(
          unless(anyOf(
              // Methods are covered by the method matchers.
              cxxMethodDecl(),
              // Out-of-line overloaded operators have special names and should
              // never be renamed.
              isOverloadedOperator(),
              // Must be checked after filtering out overloaded operators to
              // prevent asserts about the identifier not being a simple name.
              isBlacklistedFunction())),
          in_blink_namespace));
  FunctionDeclRewriter function_decl_rewriter(&replacements);
  match_finder.addMatcher(function_decl_matcher, &function_decl_rewriter);

  // Non-method function references ========
  // Given
  //   f();
  //   void (*p)() = &f;
  // matches |f()| and |&f|.
  auto function_ref_matcher = id(
      "expr", declRefExpr(to(function_decl_matcher),
                          // Ignore template substitutions.
                          unless(hasAncestor(substNonTypeTemplateParmExpr()))));
  FunctionRefRewriter function_ref_rewriter(&replacements);
  match_finder.addMatcher(function_ref_matcher, &function_ref_rewriter);

  // Method declarations ========
  // Given
  //   struct S {
  //     void g();
  //   };
  // matches |g|.
  // For a method to be considered for rewrite, it must not override something
  // that we're not rewriting. Any methods that we would not normally consider
  // but that override something we are rewriting should also be rewritten. So
  // we use includeAllOverriddenMethods() to check these rules not just for the
  // method being matched but for the methods it overrides also.
  auto is_blink_method = includeAllOverriddenMethods(
      allOf(in_blink_namespace, unless(isBlacklistedMethod())));
  auto method_decl_matcher = id(
      "decl",
      cxxMethodDecl(
          unless(anyOf(
              // Overloaded operators have special names and should never be
              // renamed.
              isOverloadedOperator(),
              // Similarly, constructors, destructors, and conversion
              // functions should not be considered for renaming.
              cxxConstructorDecl(), cxxDestructorDecl(), cxxConversionDecl())),
          // Check this last after excluding things, to avoid
          // asserts about overriding non-blink and blink for the
          // same method.
          is_blink_method));
  MethodDeclRewriter method_decl_rewriter(&replacements);
  match_finder.addMatcher(method_decl_matcher, &method_decl_rewriter);

  // Method references in a non-member context ========
  // Given
  //   S s;
  //   s.g();
  //   void (S::*p)() = &S::g;
  // matches |&S::g| but not |s.g()|.
  auto method_ref_matcher = id(
      "expr", declRefExpr(to(method_decl_matcher),
                          // Ignore template substitutions.
                          unless(hasAncestor(substNonTypeTemplateParmExpr()))));

  MethodRefRewriter method_ref_rewriter(&replacements);
  match_finder.addMatcher(method_ref_matcher, &method_ref_rewriter);

  // Method references in a member context ========
  // Given
  //   S s;
  //   s.g();
  //   void (S::*p)() = &S::g;
  // matches |s.g()| but not |&S::g|.
  auto method_member_matcher =
      id("expr", memberExpr(member(method_decl_matcher)));

  MethodMemberRewriter method_member_rewriter(&replacements);
  match_finder.addMatcher(method_member_matcher, &method_member_rewriter);

  // Initializers ========
  // Given
  //   struct S {
  //     int x;
  //     S() : x(2) {}
  //   };
  // matches each initializer in the constructor for S.
  auto constructor_initializer_matcher =
      cxxConstructorDecl(forEachConstructorInitializer(id(
          "initializer",
          cxxCtorInitializer(forAnyField(field_decl_matcher), isWritten()))));

  ConstructorInitializerRewriter constructor_initializer_rewriter(
      &replacements);
  match_finder.addMatcher(constructor_initializer_matcher,
                          &constructor_initializer_rewriter);

  // Unresolved lookup expressions ========
  // Given
  //   template<typename T> void F(T) { }
  //   template<void G(T)> H(T) { }
  //   H<F<int>>(...);
  // matches |F| in |H<F<int>>|.
  //
  // UnresolvedLookupExprs are similar to DeclRefExprs that reference a
  // FunctionDecl, but are used when a candidate FunctionDecl can't be selected.
  // This commonly happens inside uninstantiated template definitions for one of
  // two reasons:
  //
  // 1. If the candidate declaration is a dependent FunctionTemplateDecl, the
  //    actual overload can't be selected until template instantiation time.
  // 2. Alternatively, there might be multiple declarations in the candidate set
  //    if the candidate function has overloads. If any of the function
  //    arguments has a dependent type, then the actual overload can't be
  //    selected until instantiation time either.
  //
  // Another instance where UnresolvedLookupExprs can appear is in a template
  // argument list, like the provided example.
  auto function_template_decl_matcher =
      id("decl", functionTemplateDecl(templatedDecl(function_decl_matcher)));
  auto method_template_decl_matcher =
      id("decl", functionTemplateDecl(templatedDecl(method_decl_matcher)));
  auto unresolved_lookup_matcher = expr(id(
      "expr",
      unresolvedLookupExpr(
          // In order to automatically rename an unresolved lookup, the lookup
          // candidates must either all be Blink functions/function templates or
          // all be Blink methods/method templates. Otherwise, we might end up
          // in a situation where the naming could change depending on the
          // selected candidate.
          anyOf(allOverloadsMatch(anyOf(function_decl_matcher,
                                        function_template_decl_matcher)),
                // Note: this matches references to methods in a non-member
                // context, e.g. Template<&Class::Method>. This and the
                // UnresolvedMemberExpr matcher below are analogous to how the
                // rewriter has both a MemberRefRewriter matcher to rewrite
                // &T::method and a MethodMemberRewriter matcher to rewriter
                // t.method().
                allOverloadsMatch(anyOf(method_decl_matcher,
                                        method_template_decl_matcher))))));
  UnresolvedLookupRewriter unresolved_lookup_rewriter(&replacements);
  match_finder.addMatcher(unresolved_lookup_matcher,
                          &unresolved_lookup_rewriter);

  // Unresolved member expressions (for non-dependent fields / methods) ========
  // Similar to unresolved lookup expressions, but for methods in a member
  // context, e.g. var_with_templated_type.Method().
  auto unresolved_member_matcher = expr(id(
      "expr",
      unresolvedMemberExpr(
          // Similar to UnresolvedLookupExprs, all the candidate methods must be
          // Blink methods/method templates.
          allOverloadsMatch(
              anyOf(method_decl_matcher, method_template_decl_matcher)))));
  UnresolvedMemberRewriter unresolved_member_rewriter(&replacements);
  match_finder.addMatcher(unresolved_member_matcher,
                          &unresolved_member_rewriter);

  // Unresolved using value decls ========
  // Example:
  //  template <typename T>
  //  class BaseClass {
  //   public:
  //    unsigned long m_size;
  //  };
  //  template <typename T>
  //  class DerivedClass : protected BaseClass<T> {
  //   private:
  //    using Base = BaseClass<T>;
  //    using Base::m_size;  // <- |m_size| here is matched by
  //    void method() {      //    |unresolved_using_value_decl_matcher|.
  //      m_size = 123;  // <- |m_size| here is matched by
  //    }                //    |unresolved_dependent_using_matcher|.
  //  };
  auto unresolved_dependent_using_matcher =
      expr(id("expr", unresolvedMemberExpr(allOverloadsMatch(allOf(
                          in_blink_namespace, unresolvedUsingValueDecl())))));
  UnresolvedDependentMemberRewriter unresolved_dependent_member_rewriter(
      &replacements);
  match_finder.addMatcher(unresolved_dependent_using_matcher,
                          &unresolved_dependent_member_rewriter);
  auto unresolved_using_value_decl_matcher =
      decl(id("decl", unresolvedUsingValueDecl(in_blink_namespace)));
  UnresolvedUsingValueDeclRewriter unresolved_using_value_decl_rewriter(
      &replacements);
  match_finder.addMatcher(unresolved_using_value_decl_matcher,
                          &unresolved_using_value_decl_rewriter);

  // Using declarations ========
  // Given
  //   using blink::X;
  // matches |using blink::X|.
  auto using_decl_matcher = id(
      "decl", usingDecl(hasAnyUsingShadowDecl(hasTargetDecl(anyOf(
                  var_decl_matcher, field_decl_matcher, function_decl_matcher,
                  method_decl_matcher, function_template_decl_matcher,
                  method_template_decl_matcher, enum_member_decl_matcher)))));
  UsingDeclRewriter using_decl_rewriter(&replacements);
  match_finder.addMatcher(using_decl_matcher, &using_decl_rewriter);

  // Matches any QualType that refers to a blink type:
  // - const blink::Foo&
  // - blink::Foo*
  // - blink::Foo<T>
  // - ...
  // TODO(lukasza): The matchers below can be simplified after
  // https://llvm.org/bugs/show_bug.cgi?id=30331 is fixed.
  // Simplified matchers:
  //    auto blink_qual_type_base_matcher =
  //        qualType(hasDeclaration(in_blink_namespace));
  //    auto blink_qual_type_matcher = qualType(anyOf(
  //        blink_qual_type_base_matcher,
  //        pointsTo(blink_qual_type_base_matcher),
  //        references(blink_qual_type_base_matcher)));
  auto blink_qual_type_bug_workaround_matcher1 = hasBaseType(
      anyOf(enumType(hasDeclaration(in_blink_namespace)),
            recordType(hasDeclaration(in_blink_namespace)),
            templateSpecializationType(hasDeclaration(in_blink_namespace)),
            templateTypeParmType(hasDeclaration(in_blink_namespace)),
            typedefType(hasDeclaration(in_blink_namespace))));
  auto blink_qual_type_base_matcher =
      qualType(anyOf(blink_qual_type_bug_workaround_matcher1,
                     hasBaseType(elaboratedType(
                         namesType(blink_qual_type_bug_workaround_matcher1)))));
  auto blink_qual_type_matcher =
      qualType(anyOf(blink_qual_type_base_matcher, pointsTo(in_blink_namespace),
                     references(in_blink_namespace)));

  // Template-dependent decl lookup ========
  // Given
  //   template <typename T> void f() { T::foo(); }
  // matches |T::foo|.
  auto dependent_scope_decl_ref_expr_matcher =
      expr(id("expr", dependentScopeDeclRefExpr(has(nestedNameSpecifier(
                          specifiesType(blink_qual_type_matcher))))));
  DependentScopeDeclRefExprRewriter dependent_scope_decl_ref_expr_rewriter(
      &replacements);
  match_finder.addMatcher(dependent_scope_decl_ref_expr_matcher,
                          &dependent_scope_decl_ref_expr_rewriter);

  // Template-dependent member lookup ========
  // Given
  //   template <typename T>
  //   class Foo {
  //     void f() { T::foo(); }
  //     void g(T x) { x.bar(); }
  //   };
  // matches |T::foo| and |x.bar|.
  auto cxx_dependent_scope_member_expr_matcher =
      expr(id("expr", cxxDependentScopeMemberExpr(
                          hasMemberFromType(blink_qual_type_matcher))));
  CXXDependentScopeMemberExprRewriter cxx_dependent_scope_member_expr_rewriter(
      &replacements);
  match_finder.addMatcher(cxx_dependent_scope_member_expr_matcher,
                          &cxx_dependent_scope_member_expr_rewriter);

  std::unique_ptr<clang::tooling::FrontendActionFactory> factory =
      clang::tooling::newFrontendActionFactory(&match_finder);
  int result = tool.run(factory.get());
  if (result != 0)
    return result;

#if defined(_WIN32)
  HANDLE lockfd = CreateFile("rewrite-sym.lock", GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  OVERLAPPED overlapped = {};
  LockFileEx(lockfd, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped);
#else
  int lockfd = open("rewrite-sym.lock", O_RDWR | O_CREAT, 0666);
  while (flock(lockfd, LOCK_EX)) {  // :D
  }
#endif

  std::ofstream replacement_db_file("rewrite-sym.txt",
                                    std::ios_base::out | std::ios_base::app);
  for (const auto& p : field_decl_rewriter.replacement_names())
    replacement_db_file << "var:" << p.first << ":" << p.second << "\n";
  for (const auto& p : var_decl_rewriter.replacement_names())
    replacement_db_file << "var:" << p.first << ":" << p.second << "\n";
  for (const auto& p : enum_member_decl_rewriter.replacement_names())
    replacement_db_file << "enu:" << p.first << ":" << p.second << "\n";
  for (const auto& p : function_decl_rewriter.replacement_names())
    replacement_db_file << "fun:" << p.first << ":" << p.second << "\n";
  for (const auto& p : method_decl_rewriter.replacement_names())
    replacement_db_file << "fun:" << p.first << ":" << p.second << "\n";
  replacement_db_file.close();

#if defined(_WIN32)
  UnlockFileEx(lockfd, 0, 1, 0, &overlapped);
  CloseHandle(lockfd);
#else
  flock(lockfd, LOCK_UN);
  close(lockfd);
#endif

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

// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This clang plugin checks various invariants of the Blink garbage
// collection infrastructure.
//
// Errors are described at:
// http://www.chromium.org/developers/blink-gc-plugin-errors

#include "BlinkGCPluginConsumer.h"
#include "BlinkGCPluginOptions.h"
#include "Config.h"

#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"

using namespace clang;

class BlinkGCPluginAction : public PluginASTAction {
 public:
  BlinkGCPluginAction() {}

 protected:
  // Overridden from PluginASTAction:
  virtual std::unique_ptr<ASTConsumer> CreateASTConsumer(
      CompilerInstance& instance,
      llvm::StringRef ref) {
    return llvm::make_unique<BlinkGCPluginConsumer>(instance, options_);
  }

  virtual bool ParseArgs(const CompilerInstance&,
                         const std::vector<std::string>& args) {
    for (const auto& arg : args) {
      if (arg == "dump-graph") {
        options_.dump_graph = true;
      } else if (arg == "warn-unneeded-finalizer") {
        options_.warn_unneeded_finalizer = true;
      } else {
        llvm::errs() << "Unknown blink-gc-plugin argument: " << arg << "\n";
        return false;
      }
    }
    return true;
  }

 private:
  BlinkGCPluginOptions options_;
};

static FrontendPluginRegistry::Add<BlinkGCPluginAction> X(
    "blink-gc-plugin",
    "Check Blink GC invariants");

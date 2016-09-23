// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_GN_ARGS_H_
#define TOOLS_GN_ARGS_H_

#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "tools/gn/scope.h"

class Err;

extern const char kBuildArgs_Help[];

// Manages build arguments. It stores the global arguments specified on the
// command line, and sets up the root scope with the proper values.
//
// This class tracks accesses so we can report errors about unused variables.
// The use case is if the user specifies an override on the command line, but
// no buildfile actually uses that variable. We want to be able to report that
// the argument was unused.
class Args {
 public:
  Args();
  Args(const Args& other);
  ~Args();

  // Specifies overrides of the build arguments. These are normally specified
  // on the command line.
  void AddArgOverride(const char* name, const Value& value);
  void AddArgOverrides(const Scope::KeyValueMap& overrides);

  // Returns the value corresponding to the given argument name, or NULL if no
  // argument is set.
  const Value* GetArgOverride(const char* name) const;

  // Gets all overrides set on the build.
  Scope::KeyValueMap GetAllOverrides() const;

  // Sets up the root scope for a toolchain. This applies the default system
  // flags and saves the toolchain overrides so they can be applied to
  // declare_args blocks that appear when loading files in that toolchain.
  void SetupRootScope(Scope* dest,
                      const Scope::KeyValueMap& toolchain_overrides) const;

  // Sets up the given scope with arguments passed in.
  //
  // If the values specified in the args are not already set, the values in
  // the args list will be used (which are assumed to be the defaults), but
  // they will not override the system defaults or the current overrides.
  //
  // All args specified in the input will be marked as "used".
  //
  // On failure, the err will be set and it will return false.
  bool DeclareArgs(const Scope::KeyValueMap& args,
                   Scope* scope_to_set,
                   Err* err) const;

  // Checks to see if any of the overrides ever used were never declared as
  // arguments. If there are, this returns false and sets the error.
  bool VerifyAllOverridesUsed(Err* err) const;

  // Adds all declared arguments to the given output list. If the values exist
  // in the list already, their values will be overwriten, but other values
  // already in the list will remain.
  void MergeDeclaredArguments(Scope::KeyValueMap* dest) const;

 private:
  using ArgumentsPerToolchain =
      base::hash_map<const Settings*, Scope::KeyValueMap>;

  // Sets the default config based on the current system.
  void SetSystemVarsLocked(Scope* scope) const;

  // Sets the given already declared vars on the given scope.
  void ApplyOverridesLocked(const Scope::KeyValueMap& values,
                            Scope* scope) const;

  void SaveOverrideRecordLocked(const Scope::KeyValueMap& values) const;

  // Returns the KeyValueMap used for arguments declared for the specified
  // toolchain.
  Scope::KeyValueMap& DeclaredArgumentsForToolchainLocked(Scope* scope) const;

  // Returns the KeyValueMap used for overrides for the specified
  // toolchain.
  Scope::KeyValueMap& OverridesForToolchainLocked(Scope* scope) const;

  // Since this is called during setup which we assume is single-threaded,
  // this is not protected by the lock. It should be set only during init.
  Scope::KeyValueMap overrides_;

  mutable base::Lock lock_;

  // Maintains a list of all overrides we've ever seen. This is the main
  // |overrides_| as well as toolchain overrides. Tracking this allows us to
  // check for overrides that were specified but never used.
  mutable Scope::KeyValueMap all_overrides_;

  // Maps from Settings (which corresponds to a toolchain) to the map of
  // declared variables. This is used to tracks all variables declared in any
  // buildfile. This is so we can see if the user set variables on the command
  // line that are not used anywhere. Each map is toolchain specific as each
  // toolchain may define variables in different locations.
  mutable ArgumentsPerToolchain declared_arguments_per_toolchain_;

  // Overrides for individual toolchains. This is necessary so we
  // can apply the correct override for the current toolchain, once
  // we see an argument declaration.
  mutable ArgumentsPerToolchain toolchain_overrides_;

  DISALLOW_ASSIGN(Args);
};

#endif  // TOOLS_GN_ARGS_H_

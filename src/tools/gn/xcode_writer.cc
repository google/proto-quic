// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/xcode_writer.h"

#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "base/environment.h"
#include "base/logging.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "tools/gn/args.h"
#include "tools/gn/build_settings.h"
#include "tools/gn/builder.h"
#include "tools/gn/commands.h"
#include "tools/gn/deps_iterator.h"
#include "tools/gn/filesystem_utils.h"
#include "tools/gn/settings.h"
#include "tools/gn/source_file.h"
#include "tools/gn/target.h"
#include "tools/gn/value.h"
#include "tools/gn/variables.h"
#include "tools/gn/xcode_object.h"

namespace {

using TargetToFileList = std::unordered_map<const Target*, Target::FileList>;
using TargetToNativeTarget =
    std::unordered_map<const Target*, PBXNativeTarget*>;
using FileToTargets = std::map<SourceFile,
                               std::vector<const Target*>,
                               bool (*)(const SourceFile&, const SourceFile&)>;

const char kEarlGreyFileNameIdentifier[] = "egtest.mm";
const char kXCTestFileNameIdentifier[] = "xctest.mm";
const char kXCTestModuleTargetNamePostfix[] = "_module";
const char kXCTestFileReferenceFolder[] = "xctests/";

struct SafeEnvironmentVariableInfo {
  const char* name;
  bool capture_at_generation;
};

SafeEnvironmentVariableInfo kSafeEnvironmentVariables[] = {
    {"HOME", true}, {"LANG", true},    {"PATH", true},
    {"USER", true}, {"TMPDIR", false},
};

bool CompareSourceFiles(const SourceFile& lhs, const SourceFile& rhs) {
  if (lhs.GetName() < rhs.GetName())
    return true;
  else if (lhs.GetName() > rhs.GetName())
    return false;
  else
    return lhs.value() < rhs.value();
}

XcodeWriter::TargetOsType GetTargetOs(const Args& args) {
  const Value* target_os_value = args.GetArgOverride(variables::kTargetOs);
  if (target_os_value) {
    if (target_os_value->type() == Value::STRING) {
      if (target_os_value->string_value() == "ios")
        return XcodeWriter::WRITER_TARGET_OS_IOS;
    }
  }
  return XcodeWriter::WRITER_TARGET_OS_MACOS;
}

std::string GetBuildScript(const std::string& target_name,
                           const std::string& ninja_extra_args,
                           base::Environment* environment) {
  std::stringstream script;
  script << "echo note: \"Compile and copy " << target_name << " via ninja\"\n"
         << "exec ";

  // Launch ninja with a sanitized environment (Xcode sets many environment
  // variable overridding settings, including the SDK, thus breaking hermetic
  // build).
  script << "env -i ";
  for (const auto& variable : kSafeEnvironmentVariables) {
    script << variable.name << "=\"";

    std::string value;
    if (variable.capture_at_generation)
      environment->GetVar(variable.name, &value);

    if (!value.empty())
      script << value;
    else
      script << "$" << variable.name;
    script << "\" ";
  }

  script << "ninja -C .";
  if (!ninja_extra_args.empty())
    script << " " << ninja_extra_args;
  if (!target_name.empty())
    script << " " << target_name;
  script << "\nexit 1\n";
  return script.str();
}

bool IsApplicationTarget(const Target* target) {
  return target->output_type() == Target::CREATE_BUNDLE &&
         target->bundle_data().product_type() ==
             "com.apple.product-type.application";
}

bool IsXCTestModuleTarget(const Target* target) {
  return target->output_type() == Target::CREATE_BUNDLE &&
         target->bundle_data().product_type() ==
             "com.apple.product-type.bundle.unit-test" &&
         base::EndsWith(target->label().name(), kXCTestModuleTargetNamePostfix,
                        base::CompareCase::SENSITIVE);
}

const Target* FindXCTestApplicationTarget(
    const Target* xctest_module_target,
    const std::vector<const Target*>& targets) {
  DCHECK(IsXCTestModuleTarget(xctest_module_target));
  DCHECK(base::EndsWith(xctest_module_target->label().name(),
                        kXCTestModuleTargetNamePostfix,
                        base::CompareCase::SENSITIVE));
  std::string application_target_name =
      xctest_module_target->label().name().substr(
          0, xctest_module_target->label().name().size() -
                 strlen(kXCTestModuleTargetNamePostfix));
  for (const Target* target : targets) {
    if (target->label().name() == application_target_name) {
      return target;
    }
  }
  NOTREACHED();
  return nullptr;
}

// Returns the corresponding application targets given XCTest module targets.
void FindXCTestApplicationTargets(
    const std::vector<const Target*>& xctest_module_targets,
    const std::vector<const Target*>& targets,
    std::vector<const Target*>* xctest_application_targets) {
  for (const Target* xctest_module_target : xctest_module_targets) {
    xctest_application_targets->push_back(
        FindXCTestApplicationTarget(xctest_module_target, targets));
  }
}

// Searches the list of xctest files recursively under |target|.
void SearchXCTestFiles(const Target* target,
                       TargetToFileList* xctest_files_per_target) {
  // Early return if already visited and processed.
  if (xctest_files_per_target->find(target) != xctest_files_per_target->end())
    return;

  Target::FileList xctest_files;
  for (const SourceFile& file : target->sources()) {
    if (base::EndsWith(file.GetName(), kEarlGreyFileNameIdentifier,
                       base::CompareCase::SENSITIVE) ||
        base::EndsWith(file.GetName(), kXCTestFileNameIdentifier,
                       base::CompareCase::SENSITIVE)) {
      xctest_files.push_back(file);
    }
  }

  // Call recursively on public and private deps.
  for (const auto& t : target->public_deps()) {
    SearchXCTestFiles(t.ptr, xctest_files_per_target);
    const Target::FileList& deps_xctest_files =
        (*xctest_files_per_target)[t.ptr];
    xctest_files.insert(xctest_files.end(), deps_xctest_files.begin(),
                        deps_xctest_files.end());
  }

  for (const auto& t : target->private_deps()) {
    SearchXCTestFiles(t.ptr, xctest_files_per_target);
    const Target::FileList& deps_xctest_files =
        (*xctest_files_per_target)[t.ptr];
    xctest_files.insert(xctest_files.end(), deps_xctest_files.begin(),
                        deps_xctest_files.end());
  }

  // Sort xctest_files to remove duplicates.
  std::sort(xctest_files.begin(), xctest_files.end());
  xctest_files.erase(std::unique(xctest_files.begin(), xctest_files.end()),
                     xctest_files.end());

  xctest_files_per_target->insert(std::make_pair(target, xctest_files));
}

// Finds the list of xctest files recursively under each of the application
// targets.
void FindXCTestFilesForTargets(
    const std::vector<const Target*>& application_targets,
    std::vector<Target::FileList>* file_lists) {
  TargetToFileList xctest_files_per_target;

  for (const Target* target : application_targets) {
    DCHECK(IsApplicationTarget(target));
    SearchXCTestFiles(target, &xctest_files_per_target);
    file_lists->push_back(xctest_files_per_target[target]);
  }
}

// Maps each xctest file to a list of xctest application targets that contains
// the file.
void MapXCTestFileToApplicationTargets(
    const std::vector<const Target*>& xctest_application_targets,
    const std::vector<Target::FileList>& xctest_file_lists,
    FileToTargets* xctest_file_to_application_targets) {
  DCHECK_EQ(xctest_application_targets.size(), xctest_file_lists.size());

  for (size_t i = 0; i < xctest_application_targets.size(); ++i) {
    const Target* xctest_application_target = xctest_application_targets[i];
    DCHECK(IsApplicationTarget(xctest_application_target));

    for (const SourceFile& source : xctest_file_lists[i]) {
      auto iter = xctest_file_to_application_targets->find(source);
      if (iter == xctest_file_to_application_targets->end()) {
        iter =
            xctest_file_to_application_targets
                ->insert(std::make_pair(source, std::vector<const Target*>()))
                .first;
      }
      iter->second.push_back(xctest_application_target);
    }
  }
}

class CollectPBXObjectsPerClassHelper : public PBXObjectVisitor {
 public:
  CollectPBXObjectsPerClassHelper() {}

  void Visit(PBXObject* object) override {
    DCHECK(object);
    objects_per_class_[object->Class()].push_back(object);
  }

  const std::map<PBXObjectClass, std::vector<const PBXObject*>>&
  objects_per_class() const {
    return objects_per_class_;
  }

 private:
  std::map<PBXObjectClass, std::vector<const PBXObject*>> objects_per_class_;

  DISALLOW_COPY_AND_ASSIGN(CollectPBXObjectsPerClassHelper);
};

std::map<PBXObjectClass, std::vector<const PBXObject*>>
CollectPBXObjectsPerClass(PBXProject* project) {
  CollectPBXObjectsPerClassHelper visitor;
  project->Visit(visitor);
  return visitor.objects_per_class();
}

class RecursivelyAssignIdsHelper : public PBXObjectVisitor {
 public:
  RecursivelyAssignIdsHelper(const std::string& seed)
      : seed_(seed), counter_(0) {}

  void Visit(PBXObject* object) override {
    std::stringstream buffer;
    buffer << seed_ << " " << object->Name() << " " << counter_;
    std::string hash = base::SHA1HashString(buffer.str());
    DCHECK_EQ(hash.size() % 4, 0u);

    uint32_t id[3] = {0, 0, 0};
    const uint32_t* ptr = reinterpret_cast<const uint32_t*>(hash.data());
    for (size_t i = 0; i < hash.size() / 4; i++)
      id[i % 3] ^= ptr[i];

    object->SetId(base::HexEncode(id, sizeof(id)));
    ++counter_;
  }

 private:
  std::string seed_;
  int64_t counter_;

  DISALLOW_COPY_AND_ASSIGN(RecursivelyAssignIdsHelper);
};

void RecursivelyAssignIds(PBXProject* project) {
  RecursivelyAssignIdsHelper visitor(project->Name());
  project->Visit(visitor);
}

}  // namespace

// static
bool XcodeWriter::RunAndWriteFiles(const std::string& workspace_name,
                                   const std::string& root_target_name,
                                   const std::string& ninja_extra_args,
                                   const std::string& dir_filters_string,
                                   const BuildSettings* build_settings,
                                   const Builder& builder,
                                   Err* err) {
  const XcodeWriter::TargetOsType target_os =
      GetTargetOs(build_settings->build_args());

  PBXAttributes attributes;
  switch (target_os) {
    case XcodeWriter::WRITER_TARGET_OS_IOS:
      attributes["SDKROOT"] = "iphoneos";
      attributes["TARGETED_DEVICE_FAMILY"] = "1,2";
      break;
    case XcodeWriter::WRITER_TARGET_OS_MACOS:
      attributes["SDKROOT"] = "macosx";
      break;
  }

  const std::string source_path =
      base::FilePath::FromUTF8Unsafe(
          RebasePath("//", build_settings->build_dir()))
          .StripTrailingSeparators()
          .AsUTF8Unsafe();

  std::string config_name = build_settings->build_dir()
                                .Resolve(base::FilePath())
                                .StripTrailingSeparators()
                                .BaseName()
                                .AsUTF8Unsafe();
  DCHECK(!config_name.empty());

  std::string::size_type separator = config_name.find('-');
  if (separator != std::string::npos)
    config_name = config_name.substr(0, separator);

  std::vector<const Target*> targets;
  std::vector<const Target*> all_targets = builder.GetAllResolvedTargets();
  if (!XcodeWriter::FilterTargets(build_settings, all_targets,
                                  dir_filters_string, &targets, err)) {
    return false;
  }

  XcodeWriter workspace(workspace_name);
  workspace.CreateProductsProject(targets, attributes, source_path, config_name,
                                  root_target_name, ninja_extra_args,
                                  build_settings, target_os);

  workspace.CreateSourcesProject(
      all_targets, build_settings->build_dir(), attributes, source_path,
      build_settings->root_path_utf8(), config_name, target_os);

  return workspace.WriteFiles(build_settings, err);
}

XcodeWriter::XcodeWriter(const std::string& name) : name_(name) {
  if (name_.empty())
    name_.assign("all");
}

XcodeWriter::~XcodeWriter() {}

// static
bool XcodeWriter::FilterTargets(const BuildSettings* build_settings,
                                const std::vector<const Target*>& all_targets,
                                const std::string& dir_filters_string,
                                std::vector<const Target*>* targets,
                                Err* err) {
  // Filter targets according to the semicolon-delimited list of label patterns,
  // if defined, first.
  targets->reserve(all_targets.size());
  if (dir_filters_string.empty()) {
    *targets = all_targets;
  } else {
    std::vector<LabelPattern> filters;
    if (!commands::FilterPatternsFromString(build_settings, dir_filters_string,
                                            &filters, err)) {
      return false;
    }

    commands::FilterTargetsByPatterns(all_targets, filters, targets);
  }

  // Filter out all target of type EXECUTABLE that are direct dependency of
  // a BUNDLE_DATA target (under the assumption that they will be part of a
  // CREATE_BUNDLE target generating an application bundle). Sort the list
  // of targets per pointer to use binary search for the removal.
  std::sort(targets->begin(), targets->end());

  for (const Target* target : all_targets) {
    if (!target->settings()->is_default())
      continue;

    if (target->output_type() != Target::BUNDLE_DATA)
      continue;

    for (const auto& pair : target->GetDeps(Target::DEPS_LINKED)) {
      if (pair.ptr->output_type() != Target::EXECUTABLE)
        continue;

      auto iter = std::lower_bound(targets->begin(), targets->end(), pair.ptr);
      if (iter != targets->end() && *iter == pair.ptr)
        targets->erase(iter);
    }
  }

  // Sort the list of targets per-label to get a consistent ordering of them
  // in the generated Xcode project (and thus stability of the file generated).
  std::sort(targets->begin(), targets->end(),
            [](const Target* a, const Target* b) {
              return a->label().name() < b->label().name();
            });

  return true;
}

// static
void XcodeWriter::FilterXCTestModuleTargets(
    const std::vector<const Target*>& targets,
    std::vector<const Target*>* xctest_module_targets) {
  for (const Target* target : targets) {
    if (!IsXCTestModuleTarget(target))
      continue;

    xctest_module_targets->push_back(target);
  }
}

void XcodeWriter::CreateProductsProject(
    const std::vector<const Target*>& targets,
    const PBXAttributes& attributes,
    const std::string& source_path,
    const std::string& config_name,
    const std::string& root_target,
    const std::string& ninja_extra_args,
    const BuildSettings* build_settings,
    TargetOsType target_os) {
  std::unique_ptr<PBXProject> main_project(
      new PBXProject("products", config_name, source_path, attributes));

  // Filter xctest module and application targets and find list of xctest files
  // recursively under them.
  std::vector<const Target*> xctest_module_targets;
  FilterXCTestModuleTargets(targets, &xctest_module_targets);

  std::vector<const Target*> xctest_application_targets;
  FindXCTestApplicationTargets(xctest_module_targets, targets,
                               &xctest_application_targets);
  DCHECK_EQ(xctest_module_targets.size(), xctest_application_targets.size());

  std::vector<Target::FileList> xctest_file_lists;
  FindXCTestFilesForTargets(xctest_application_targets, &xctest_file_lists);
  DCHECK_EQ(xctest_application_targets.size(), xctest_file_lists.size());

  std::string build_path;
  std::unique_ptr<base::Environment> env(base::Environment::Create());

  main_project->AddAggregateTarget(
      "All", GetBuildScript(root_target, ninja_extra_args, env.get()));

  TargetToNativeTarget xctest_application_to_module_native_target;

  for (const Target* target : targets) {
    switch (target->output_type()) {
      case Target::EXECUTABLE:
        if (target_os == XcodeWriter::WRITER_TARGET_OS_IOS)
          continue;

        main_project->AddNativeTarget(
            target->label().name(), "compiled.mach-o.executable",
            target->output_name().empty() ? target->label().name()
                                          : target->output_name(),
            "com.apple.product-type.tool",
            GetBuildScript(target->label().name(), ninja_extra_args,
                           env.get()));
        break;

      case Target::CREATE_BUNDLE: {
        if (target->bundle_data().product_type().empty())
          continue;

        // Test files need to be known to Xcode for proper indexing and for
        // discovery of tests function for XCTest, but the compilation is done
        // via ninja and thus must prevent Xcode from linking object files via
        // this hack.
        PBXAttributes extra_attributes;
        if (IsXCTestModuleTarget(target)) {
          extra_attributes["OTHER_LDFLAGS"] = "-help";
          extra_attributes["ONLY_ACTIVE_ARCH"] = "YES";
          extra_attributes["DEBUG_INFORMATION_FORMAT"] = "dwarf";
        }

        PBXNativeTarget* native_target = main_project->AddNativeTarget(
            target->label().name(), std::string(),
            RebasePath(target->bundle_data()
                           .GetBundleRootDirOutput(target->settings())
                           .value(),
                       build_settings->build_dir()),
            target->bundle_data().product_type(),
            GetBuildScript(target->label().name(), ninja_extra_args, env.get()),
            extra_attributes);

        if (!IsXCTestModuleTarget(target))
          continue;

        // Populate |xctest_application_to_module_native_target| for XCTest
        // module targets.
        const Target* application_target =
            FindXCTestApplicationTarget(target, xctest_application_targets);
        xctest_application_to_module_native_target.insert(
            std::make_pair(application_target, native_target));

        break;
      }

      default:
        break;
    }
  }

  FileToTargets xctest_file_to_application_targets(CompareSourceFiles);
  MapXCTestFileToApplicationTargets(xctest_application_targets,
                                    xctest_file_lists,
                                    &xctest_file_to_application_targets);

  // Add xctest files to the "Compiler Sources" of corresponding xctest native
  // targets.
  SourceDir source_dir("//");
  for (const auto& item : xctest_file_to_application_targets) {
    const SourceFile& source = item.first;
    for (const Target* xctest_application_target : item.second) {
      std::string navigator_path =
          kXCTestFileReferenceFolder + source.GetName();
      std::string source_path = RebasePath(source.value(), source_dir,
                                           build_settings->root_path_utf8());
      PBXNativeTarget* xctest_module_native_target =
          xctest_application_to_module_native_target[xctest_application_target];

      // Test files need to be known to Xcode for proper indexing and for
      // discovery of tests function for XCTest, but the compilation is done
      // via ninja and thus must prevent Xcode from compiling the files by
      // adding '-help' as per file compiler flag.
      main_project->AddSourceFile(navigator_path, source_path,
                                  CompilerFlags::HELP,
                                  xctest_module_native_target);
    }
  }

  projects_.push_back(std::move(main_project));
}

void XcodeWriter::CreateSourcesProject(
    const std::vector<const Target*>& targets,
    const SourceDir& root_build_dir,
    const PBXAttributes& attributes,
    const std::string& source_path,
    const std::string& absolute_source_path,
    const std::string& config_name,
    TargetOsType target_os) {
  std::vector<SourceFile> sources;
  for (const Target* target : targets) {
    for (const SourceFile& source : target->sources()) {
      if (IsStringInOutputDir(root_build_dir, source.value()))
        continue;

      sources.push_back(source);
    }
  }

  std::unique_ptr<PBXProject> sources_for_indexing(
      new PBXProject("sources", config_name, source_path, attributes));

  // Sort sources to ensure determinisn of the project file generation and
  // remove duplicate reference to the source files (can happen due to the
  // bundle_data targets).
  std::sort(sources.begin(), sources.end());
  sources.erase(std::unique(sources.begin(), sources.end()), sources.end());

  SourceDir source_dir("//");
  for (const SourceFile& source : sources) {
    std::string source_file =
        RebasePath(source.value(), source_dir, absolute_source_path);
    sources_for_indexing->AddSourceFileToIndexingTarget(
        source_file, source_file, CompilerFlags::NONE);
  }

  projects_.push_back(std::move(sources_for_indexing));
}

bool XcodeWriter::WriteFiles(const BuildSettings* build_settings, Err* err) {
  for (const auto& project : projects_) {
    if (!WriteProjectFile(build_settings, project.get(), err))
      return false;
  }

  SourceFile xcworkspacedata_file =
      build_settings->build_dir().ResolveRelativeFile(
          Value(nullptr, name_ + ".xcworkspace/contents.xcworkspacedata"), err);
  if (xcworkspacedata_file.is_null())
    return false;

  std::stringstream xcworkspacedata_string_out;
  WriteWorkspaceContent(xcworkspacedata_string_out);

  return WriteFileIfChanged(build_settings->GetFullPath(xcworkspacedata_file),
                            xcworkspacedata_string_out.str(), err);
}

bool XcodeWriter::WriteProjectFile(const BuildSettings* build_settings,
                                   PBXProject* project,
                                   Err* err) {
  SourceFile pbxproj_file = build_settings->build_dir().ResolveRelativeFile(
      Value(nullptr, project->Name() + ".xcodeproj/project.pbxproj"), err);
  if (pbxproj_file.is_null())
    return false;

  std::stringstream pbxproj_string_out;
  WriteProjectContent(pbxproj_string_out, project);

  if (!WriteFileIfChanged(build_settings->GetFullPath(pbxproj_file),
                          pbxproj_string_out.str(), err))
    return false;

  return true;
}

void XcodeWriter::WriteWorkspaceContent(std::ostream& out) {
  out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      << "<Workspace version = \"1.0\">\n";
  for (const auto& project : projects_) {
    out << "  <FileRef location = \"group:" << project->Name()
        << ".xcodeproj\"></FileRef>\n";
  }
  out << "</Workspace>\n";
}

void XcodeWriter::WriteProjectContent(std::ostream& out, PBXProject* project) {
  RecursivelyAssignIds(project);

  out << "// !$*UTF8*$!\n"
      << "{\n"
      << "\tarchiveVersion = 1;\n"
      << "\tclasses = {\n"
      << "\t};\n"
      << "\tobjectVersion = 46;\n"
      << "\tobjects = {\n";

  for (auto& pair : CollectPBXObjectsPerClass(project)) {
    out << "\n"
        << "/* Begin " << ToString(pair.first) << " section */\n";
    std::sort(pair.second.begin(), pair.second.end(),
              [](const PBXObject* a, const PBXObject* b) {
                return a->id() < b->id();
              });
    for (auto* object : pair.second) {
      object->Print(out, 2);
    }
    out << "/* End " << ToString(pair.first) << " section */\n";
  }

  out << "\t};\n"
      << "\trootObject = " << project->Reference() << ";\n"
      << "}\n";
}

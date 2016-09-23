// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#import <Foundation/Foundation.h>
#include <getopt.h>
#include <string>

namespace {

void PrintUsage() {
  fprintf(
      stderr,
      "Usage: iossim [-d device] [-s sdk_version] <app_path> <xctest_path>\n"
      "  where <app_path> is the path to the .app directory and <xctest_path> "
      "is the path to an optional xctest bundle.\n"
      "Options:\n"
      "  -d  Specifies the device (must be one of the values from the iOS "
      "Simulator's Hardware -> Device menu. Defaults to 'iPhone 6s'.\n"
      "  -w  Wipe the device's contents and settings before running the "
      "test.\n"
      "  -e  Specifies an environment key=value pair that will be"
      " set in the simulated application's environment.\n"
      "  -c  Specifies command line flags to pass to application.\n"
      "  -p  Print the device's home directory, does not run a test.\n"
      "  -s  Specifies the SDK version to use (e.g '9.3'). Will use system "
      "default if not specified.\n");
}

// Exit status codes.
const int kExitSuccess = EXIT_SUCCESS;
const int kExitInvalidArguments = 2;

void LogError(NSString* format, ...) {
  va_list list;
  va_start(list, format);

  NSString* message =
      [[[NSString alloc] initWithFormat:format arguments:list] autorelease];

  fprintf(stderr, "iossim: ERROR: %s\n", [message UTF8String]);
  fflush(stderr);

  va_end(list);
}

}

// Wrap boiler plate calls to xcrun NSTasks.
@interface XCRunTask : NSObject {
  NSTask* _task;
}
- (instancetype)initWithArguments:(NSArray*)arguments;
- (void)run;
- (void)setStandardOutput:(id)output;
- (void)setStandardError:(id)error;
@end

@implementation XCRunTask

- (instancetype)initWithArguments:(NSArray*)arguments {
  self = [super init];
  if (self) {
    _task = [[NSTask alloc] init];
    SEL selector = @selector(setStartsNewProcessGroup:);
    if ([_task respondsToSelector:selector])
      [_task performSelector:selector withObject:nil];
    [_task setLaunchPath:@"/usr/bin/xcrun"];
    [_task setArguments:arguments];
  }
  return self;
}

- (void)dealloc {
  [_task release];
  [super dealloc];
}

- (void)setStandardOutput:(id)output {
  [_task setStandardOutput:output];
}

- (void)setStandardError:(id)error {
  [_task setStandardError:error];
}

- (void)run {
  [_task launch];
  [_task waitUntilExit];
}

- (void)launch {
  [_task launch];
}

- (void)waitUntilExit {
  [_task waitUntilExit];
}

@end

// Return array of available iOS runtime dictionaries.  Unavailable (old Xcode
// versions) or other runtimes (tvOS, watchOS) are removed.
NSArray* Runtimes(NSDictionary* simctl_list) {
  NSMutableArray* runtimes =
      [[simctl_list[@"runtimes"] mutableCopy] autorelease];
  for (NSDictionary* runtime in simctl_list[@"runtimes"]) {
    if (![runtime[@"identifier"]
            hasPrefix:@"com.apple.CoreSimulator.SimRuntime.iOS"] ||
        ![runtime[@"availability"] isEqualToString:@"(available)"]) {
      [runtimes removeObject:runtime];
    }
  }
  return runtimes;
}

// Return array of device dictionaries.
NSArray* Devices(NSDictionary* simctl_list) {
  NSMutableArray* devicetypes =
      [[simctl_list[@"devicetypes"] mutableCopy] autorelease];
  for (NSDictionary* devicetype in simctl_list[@"devicetypes"]) {
    if (![devicetype[@"identifier"]
            hasPrefix:@"com.apple.CoreSimulator.SimDeviceType.iPad"] &&
        ![devicetype[@"identifier"]
            hasPrefix:@"com.apple.CoreSimulator.SimDeviceType.iPhone"]) {
      [devicetypes removeObject:devicetype];
    }
  }
  return devicetypes;
}

// Get list of devices, runtimes, etc from sim_ctl.
NSDictionary* GetSimulatorList() {
  XCRunTask* task = [[[XCRunTask alloc]
      initWithArguments:@[ @"simctl", @"list", @"-j" ]] autorelease];
  NSPipe* out = [NSPipe pipe];
  [task setStandardOutput:out];

  // In the rest of the this file we read from the pipe after -waitUntilExit
  // (We normally wrap -launch and -waitUntilExit in one -run method).  However,
  // on some swarming slaves this led to a hang on simctl's pipe.  Since the
  // output of simctl is so instant, reading it before exit seems to work, and
  // seems to avoid the hang.
  [task launch];
  NSData* data = [[out fileHandleForReading] readDataToEndOfFile];
  [task waitUntilExit];

  NSError* error = nil;
  return [NSJSONSerialization JSONObjectWithData:data
                                         options:kNilOptions
                                           error:&error];
}

// List supported runtimes and devices.
void PrintSupportedDevices(NSDictionary* simctl_list) {
  printf("\niOS devices:\n");
  for (NSDictionary* type in Devices(simctl_list)) {
    printf("%s\n", [type[@"name"] UTF8String]);
  }
  printf("\nruntimes:\n");
  for (NSDictionary* runtime in Runtimes(simctl_list)) {
    printf("%s\n", [runtime[@"version"] UTF8String]);
  }
}

// Expand path to absolute path.
NSString* ResolvePath(NSString* path) {
  path = [path stringByExpandingTildeInPath];
  path = [path stringByStandardizingPath];
  const char* cpath = [path cStringUsingEncoding:NSUTF8StringEncoding];
  char* resolved_name = NULL;
  char* abs_path = realpath(cpath, resolved_name);
  if (abs_path == NULL) {
    return nil;
  }
  return [NSString stringWithCString:abs_path encoding:NSUTF8StringEncoding];
}

// Search |simctl_list| for a udid matching |device_name| and |sdk_version|.
NSString* GetDeviceBySDKAndName(NSDictionary* simctl_list,
                                NSString* device_name,
                                NSString* sdk_version) {
  NSString* sdk = [@"iOS " stringByAppendingString:sdk_version];
  NSArray* devices = [simctl_list[@"devices"] objectForKey:sdk];
  for (NSDictionary* device in devices) {
    if ([device[@"name"] isEqualToString:device_name]) {
      return device[@"udid"];
    }
  }
  return nil;
}

// Prints the HOME environment variable for a device.  Used by the bots to
// package up all the test data.
void PrintDeviceHome(NSString* udid) {
  XCRunTask* task = [[[XCRunTask alloc]
      initWithArguments:@[ @"simctl", @"getenv", udid, @"HOME" ]] autorelease];
  [task run];
}

// Erase a device, used by the bots before a clean test run.
void WipeDevice(NSString* udid) {
  XCRunTask* shutdown = [[[XCRunTask alloc]
      initWithArguments:@[ @"simctl", @"shutdown", udid ]] autorelease];
  [shutdown setStandardOutput:nil];
  [shutdown setStandardError:nil];
  [shutdown run];

  XCRunTask* erase = [[[XCRunTask alloc]
      initWithArguments:@[ @"simctl", @"erase", udid ]] autorelease];
  [erase run];
}

void KillSimulator() {
  XCRunTask* task = [[[XCRunTask alloc]
      initWithArguments:@[ @"killall", @"Simulator" ]] autorelease];
  [task setStandardOutput:nil];
  [task setStandardError:nil];
  [task run];
}

void RunApplication(NSString* app_path,
                    NSString* xctest_path,
                    NSString* udid,
                    NSMutableDictionary* app_env,
                    NSString* cmd_args) {
  NSString* tempFilePath = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
  [[NSFileManager defaultManager] createFileAtPath:tempFilePath
                                          contents:nil
                                        attributes:nil];

  NSMutableDictionary* xctestrun = [NSMutableDictionary dictionary];
  NSMutableDictionary* testTargetName = [NSMutableDictionary dictionary];

  NSMutableDictionary* testingEnvironmentVariables =
      [NSMutableDictionary dictionary];
  [testingEnvironmentVariables setValue:[app_path lastPathComponent]
                                 forKey:@"IDEiPhoneInternalTestBundleName"];

  if (xctest_path) {
    [testTargetName setValue:xctest_path forKey:@"TestBundlePath"];
    NSString* inject =
        @"__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/"
         "PrivateFrameworks/IDEBundleInjection.framework/IDEBundleInjection";
    [testingEnvironmentVariables setValue:inject
                                   forKey:@"DYLD_INSERT_LIBRARIES"];
  } else {
    [testTargetName setValue:app_path forKey:@"TestBundlePath"];
  }
  [testTargetName setValue:app_path forKey:@"TestHostPath"];

  if ([app_env count]) {
    [testTargetName setObject:app_env forKey:@"EnvironmentVariables"];
  }

  if (cmd_args) {
    [testTargetName setObject:@[ cmd_args ] forKey:@"CommandLineArguments"];
  }

  [testTargetName setObject:testingEnvironmentVariables
                     forKey:@"TestingEnvironmentVariables"];
  [xctestrun setObject:testTargetName forKey:@"TestTargetName"];

  NSString* error;
  NSData* data = [NSPropertyListSerialization
      dataFromPropertyList:xctestrun
                    format:NSPropertyListXMLFormat_v1_0
          errorDescription:&error];
  [data writeToFile:tempFilePath atomically:YES];
  XCRunTask* task = [[[XCRunTask alloc] initWithArguments:@[
    @"xcodebuild", @"-xctestrun", tempFilePath, @"-destination",
    [@"platform=iOS Simulator,id=" stringByAppendingString:udid],
    @"test-without-building"
  ]] autorelease];

  if (!xctest_path) {
    // The following stderr messages are meaningless on iossim when not running
    // xctests and can be safely stripped.
    NSArray* ignore_strings = @[
      @"IDETestOperationsObserverErrorDomain", @"** TEST EXECUTE FAILED **"
    ];
    NSPipe* stderr_pipe = [NSPipe pipe];
    stderr_pipe.fileHandleForReading.readabilityHandler =
        ^(NSFileHandle* handle) {
          NSString* log = [[[NSString alloc] initWithData:handle.availableData
                                                 encoding:NSUTF8StringEncoding]
              autorelease];
          for (NSString* ignore_string in ignore_strings) {
            if ([log rangeOfString:ignore_string].location != NSNotFound) {
              return;
            }
          }
          printf("%s", [log UTF8String]);
        };
    [task setStandardError:stderr_pipe];
  }
  [task run];
}

int main(int argc, char* const argv[]) {
  // When the last running simulator is from Xcode 7, an Xcode 8 run will yeild
  // a failure to "unload a stale CoreSimulatorService job" message.  Sending a
  // hidden simctl to do something simple (list devices) helpfully works around
  // this issue.
  XCRunTask* workaround_task = [[[XCRunTask alloc]
      initWithArguments:@[ @"simctl", @"list", @"-j" ]] autorelease];
  [workaround_task setStandardOutput:nil];
  [workaround_task setStandardError:nil];
  [workaround_task run];

  NSString* app_path = nil;
  NSString* xctest_path = nil;
  NSString* cmd_args = nil;
  NSString* device_name = @"iPhone 6s";
  bool wants_wipe = false;
  bool wants_print_home = false;
  NSDictionary* simctl_list = GetSimulatorList();
  float sdk = 0;
  for (NSDictionary* runtime in Runtimes(simctl_list)) {
    sdk = fmax(sdk, [runtime[@"version"] floatValue]);
  }
  NSString* sdk_version = [NSString stringWithFormat:@"%0.1f", sdk];
  NSMutableDictionary* app_env = [NSMutableDictionary dictionary];

  int c;
  while ((c = getopt(argc, argv, "hs:d:u:t:e:c:pwl")) != -1) {
    switch (c) {
      case 's':
        sdk_version = [NSString stringWithUTF8String:optarg];
        break;
      case 'd':
        device_name = [NSString stringWithUTF8String:optarg];
        break;
      case 'w':
        wants_wipe = true;
        break;
      case 'c':
        cmd_args = [NSString stringWithUTF8String:optarg];
        break;
      case 'e': {
        NSString* envLine = [NSString stringWithUTF8String:optarg];
        NSRange range = [envLine rangeOfString:@"="];
        if (range.location == NSNotFound) {
          LogError(@"Invalid key=value argument for -e.");
          PrintUsage();
          exit(kExitInvalidArguments);
        }
        NSString* key = [envLine substringToIndex:range.location];
        NSString* value = [envLine substringFromIndex:(range.location + 1)];
        [app_env setObject:value forKey:key];
      } break;
      case 'p':
        wants_print_home = true;
        break;
      case 'l':
        PrintSupportedDevices(simctl_list);
        exit(kExitSuccess);
        break;
      case 'h':
        PrintUsage();
        exit(kExitSuccess);
      case 'u':
      case 't':
        // Ignore 'u' and 't', used by old version of iossim.
        break;
      default:
        PrintUsage();
        exit(kExitInvalidArguments);
    }
  }

  NSString* udid = GetDeviceBySDKAndName(simctl_list, device_name, sdk_version);
  if (udid == nil) {
    LogError(@"Unable to find a device %@ with SDK %@.", device_name,
             sdk_version);
    PrintSupportedDevices(simctl_list);
    exit(kExitInvalidArguments);
  }

  if (wants_print_home) {
    PrintDeviceHome(udid);
    exit(kExitSuccess);
  }

  KillSimulator();
  if (wants_wipe) {
    WipeDevice(udid);
    printf("Device wiped.\n");
    exit(kExitSuccess);
  }

  // There should be at least one arg left, specifying the app path. Any
  // additional args are passed as arguments to the app.
  if (optind < argc) {
    NSString* unresolved_path = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:argv[optind]
                                    length:strlen(argv[optind])];
    app_path = ResolvePath(unresolved_path);
    if (!app_path) {
      LogError(@"Unable to resolve app_path %@", unresolved_path);
      exit(kExitInvalidArguments);
    }

    if (++optind < argc) {
      NSString* unresolved_path = [[NSFileManager defaultManager]
          stringWithFileSystemRepresentation:argv[optind]
                                      length:strlen(argv[optind])];
      xctest_path = ResolvePath(unresolved_path);
      if (!xctest_path) {
        LogError(@"Unable to resolve xctest_path %@", unresolved_path);
        exit(kExitInvalidArguments);
      }
    }
  } else {
    LogError(@"Unable to parse command line arguments.");
    PrintUsage();
    exit(kExitInvalidArguments);
  }

  RunApplication(app_path, xctest_path, udid, app_env, cmd_args);
  KillSimulator();
  return kExitSuccess;
}

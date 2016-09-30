// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#import <Foundation/Foundation.h>
#if defined(__MAC_10_12) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_10_12
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
#else
#import <Appkit/Appkit.h>
#include <asl.h>
#import <Foundation/Foundation.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>

// An executable (iossim) that runs an app in the iOS Simulator.
// Run 'iossim -h' for usage information.
//
// For best results, the iOS Simulator application should not be running when
// iossim is invoked.
//
// Headers for iPhoneSimulatorRemoteClient and other frameworks used in this
// tool are generated by class-dump, via GYP.
// (class-dump is available at http://www.codethecode.com/projects/class-dump/)
//
// However, there are some forward declarations required to get things to
// compile.

@class DVTStackBacktrace;
#import "DVTFoundation.h"

@protocol SimBridge;
@class DVTSimulatorApplication;
@class SimDeviceSet;
@class SimDeviceType;
@class SimProfilesPathMonitor;
@class SimRuntime;
@class SimServiceConnectionManager;
#import "CoreSimulator.h"

@interface DVTPlatform : NSObject
+ (BOOL)loadAllPlatformsReturningError:(id*)arg1;
@end
@class DTiPhoneSimulatorApplicationSpecifier;
@class DTiPhoneSimulatorSession;
@class DTiPhoneSimulatorSessionConfig;
@class DTiPhoneSimulatorSystemRoot;
@class DVTConfinementServiceConnection;
@class DVTDispatchLock;
@class DVTiPhoneSimulatorMessenger;
@class DVTNotificationToken;
@class DVTTask;
// The DTiPhoneSimulatorSessionDelegate protocol is referenced
// by the iPhoneSimulatorRemoteClient framework, but not defined in the object
// file, so it must be defined here before importing the generated
// iPhoneSimulatorRemoteClient.h file.
@protocol DTiPhoneSimulatorSessionDelegate
- (void)session:(DTiPhoneSimulatorSession*)session
    didEndWithError:(NSError*)error;
- (void)session:(DTiPhoneSimulatorSession*)session
       didStart:(BOOL)started
      withError:(NSError*)error;
@end

#import "DVTiPhoneSimulatorRemoteClient.h"

// An undocumented system log key included in messages from launchd. The value
// is the PID of the process the message is about (as opposed to launchd's PID).
#define ASL_KEY_REF_PID "RefPID"

namespace {

// Name of environment variables that control the user's home directory in the
// simulator.
const char* const kUserHomeEnvVariable = "CFFIXED_USER_HOME";
const char* const kHomeEnvVariable = "HOME";

// Max number of seconds to wait for the simulator session to start.
// This timeout must allow time to start up iOS Simulator, install the app
// and perform any other black magic that is encoded in the
// iPhoneSimulatorRemoteClient framework to kick things off. Normal start up
// time is only a couple seconds but machine load, disk caches, etc., can all
// affect startup time in the wild so the timeout needs to be fairly generous.
// If this timeout occurs iossim will likely exit with non-zero status; the
// exception being if the app is invoked and completes execution before the
// session is started (this case is handled in session:didStart:withError).
const NSTimeInterval kDefaultSessionStartTimeoutSeconds = 30;

// While the simulated app is running, its stdout is redirected to a file which
// is polled by iossim and written to iossim's stdout using the following
// polling interval.
const NSTimeInterval kOutputPollIntervalSeconds = 0.1;

NSString* const kDVTFoundationRelativePath =
    @"../SharedFrameworks/DVTFoundation.framework";
NSString* const kDevToolsFoundationRelativePath =
    @"../OtherFrameworks/DevToolsFoundation.framework";
NSString* const kSimulatorRelativePath =
    @"Platforms/iPhoneSimulator.platform/Developer/Applications/"
    @"iPhone Simulator.app";

// Simulator Error String Key. This can be found by looking in the Simulator's
// Localizable.strings files.
NSString* const kSimulatorAppQuitErrorKey = @"The simulated application quit.";

const char* gToolName = "iossim";

// Exit status codes.
const int kExitSuccess = EXIT_SUCCESS;
const int kExitFailure = EXIT_FAILURE;
const int kExitInvalidArguments = 2;
const int kExitInitializationFailure = 3;
const int kExitAppFailedToStart = 4;
const int kExitAppCrashed = 5;

void LogError(NSString* format, ...) {
  va_list list;
  va_start(list, format);

  NSString* message =
      [[[NSString alloc] initWithFormat:format arguments:list] autorelease];

  fprintf(stderr, "%s: ERROR: %s\n", gToolName, [message UTF8String]);
  fflush(stderr);

  va_end(list);
}

void LogWarning(NSString* format, ...) {
  va_list list;
  va_start(list, format);

  NSString* message =
      [[[NSString alloc] initWithFormat:format arguments:list] autorelease];

  fprintf(stderr, "%s: WARNING: %s\n", gToolName, [message UTF8String]);
  fflush(stderr);

  va_end(list);
}

// Helper to find a class by name and die if it isn't found.
Class FindClassByName(NSString* nameOfClass) {
  Class theClass = NSClassFromString(nameOfClass);
  if (!theClass) {
    LogError(@"Failed to find class %@ at runtime.", nameOfClass);
    exit(kExitInitializationFailure);
  }
  return theClass;
}

// Returns the a NSString containing the stdout from running an NSTask that
// launches |toolPath| with th given command line |args|.
NSString* GetOutputFromTask(NSString* toolPath, NSArray* args) {
  NSTask* task = [[[NSTask alloc] init] autorelease];
  [task setLaunchPath:toolPath];
  [task setArguments:args];
  NSPipe* outputPipe = [NSPipe pipe];
  [task setStandardOutput:outputPipe];
  NSFileHandle* outputFile = [outputPipe fileHandleForReading];

  [task launch];
  NSData* outputData = [outputFile readDataToEndOfFile];
  [task waitUntilExit];
  if ([task isRunning]) {
    LogError(@"Task '%@ %@' is still running.",
        toolPath,
        [args componentsJoinedByString:@" "]);
    return nil;
  } else if ([task terminationStatus]) {
    LogError(@"Task '%@ %@' exited with return code %d.",
        toolPath,
        [args componentsJoinedByString:@" "],
        [task terminationStatus]);
    return nil;
  }
  return [[[NSString alloc] initWithData:outputData
                                encoding:NSUTF8StringEncoding] autorelease];
}

// Prints supported devices and SDKs.
void PrintSupportedDevices() {
  printf("Supported device/SDK combinations:\n");
  Class simDeviceSetClass = FindClassByName(@"SimDeviceSet");
  id deviceSet =
      [simDeviceSetClass setForSetPath:[simDeviceSetClass defaultSetPath]];
  for (id simDevice in [deviceSet availableDevices]) {
    NSString* deviceInfo =
        [NSString stringWithFormat:@"  -d '%@' -s '%@'\n",
            [simDevice name], [[simDevice runtime] versionString]];
    printf("%s", [deviceInfo UTF8String]);
  }
}
}  // namespace

// A delegate that is called when the simulated app is started or ended in the
// simulator.
@interface SimulatorDelegate : NSObject <DTiPhoneSimulatorSessionDelegate> {
 @private
  NSString* stdioPath_;
  NSString* developerDir_;
  NSString* simulatorHome_;
  NSThread* outputThread_;
  NSBundle* simulatorBundle_;
  BOOL appRunning_;
}
@end

// An implementation that copies the simulated app's stdio to stdout of this
// executable. While it would be nice to get stdout and stderr independently
// from iOS Simulator, issues like I/O buffering and interleaved output
// between iOS Simulator and the app would cause iossim to display things out
// of order here. Printing all output to a single file keeps the order correct.
// Instances of this classe should be initialized with the location of the
// simulated app's output file. When the simulated app starts, a thread is
// started which handles copying data from the simulated app's output file to
// the stdout of this executable.
@implementation SimulatorDelegate

// Specifies the file locations of the simulated app's stdout and stderr.
- (SimulatorDelegate*)initWithStdioPath:(NSString*)stdioPath
                           developerDir:(NSString*)developerDir
                          simulatorHome:(NSString*)simulatorHome {
  self = [super init];
  if (self) {
    stdioPath_ = [stdioPath copy];
    developerDir_ = [developerDir copy];
    simulatorHome_ = [simulatorHome copy];
  }

  return self;
}

- (void)dealloc {
  [stdioPath_ release];
  [developerDir_ release];
  [simulatorBundle_ release];
  [super dealloc];
}

// Reads data from the simulated app's output and writes it to stdout. This
// method blocks, so it should be called in a separate thread. The iOS
// Simulator takes a file path for the simulated app's stdout and stderr, but
// this path isn't always available (e.g. when the stdout is Xcode's build
// window). As a workaround, iossim creates a temp file to hold output, which
// this method reads and copies to stdout.
- (void)tailOutputForSession:(DTiPhoneSimulatorSession*)session {
  NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];

  NSFileHandle* simio = [NSFileHandle fileHandleForReadingAtPath:stdioPath_];
  NSString* versionString =
      [[[session sessionConfig] simulatedSystemRoot] sdkVersion];
  NSInteger majorVersion = [[[versionString componentsSeparatedByString:@"."]
      objectAtIndex:0] intValue];
  if (majorVersion >= 8) {
    NSString* dataPath = session.sessionConfig.device.dataPath;
    NSString* appOutput =
        [dataPath stringByAppendingPathComponent:stdioPath_];
    simio = [NSFileHandle fileHandleForReadingAtPath:appOutput];
  }
  NSFileHandle* standardOutput = [NSFileHandle fileHandleWithStandardOutput];
  // Copy data to stdout/stderr while the app is running.
  while (appRunning_) {
    NSAutoreleasePool* innerPool = [[NSAutoreleasePool alloc] init];
    [standardOutput writeData:[simio readDataToEndOfFile]];
    [NSThread sleepForTimeInterval:kOutputPollIntervalSeconds];
    [innerPool drain];
  }

  // Once the app is no longer running, copy any data that was written during
  // the last sleep cycle.
  [standardOutput writeData:[simio readDataToEndOfFile]];

  [pool drain];
}

// Fetches a localized error string from the Simulator.
- (NSString *)localizedSimulatorErrorString:(NSString*)stringKey {
  // Lazy load of the simulator bundle.
  if (simulatorBundle_ == nil) {
    NSString* simulatorPath = [developerDir_
        stringByAppendingPathComponent:kSimulatorRelativePath];
    simulatorBundle_ = [NSBundle bundleWithPath:simulatorPath];
  }
  NSString *localizedStr =
      [simulatorBundle_ localizedStringForKey:stringKey
                                        value:nil
                                        table:nil];
  if ([localizedStr length])
    return localizedStr;
  // Failed to get a value, follow Cocoa conventions and use the key as the
  // string.
  return stringKey;
}

- (void)session:(DTiPhoneSimulatorSession*)session
       didStart:(BOOL)started
      withError:(NSError*)error {
  if (!started) {
    // If the test executes very quickly (<30ms), the SimulatorDelegate may not
    // get the initial session:started:withError: message indicating successful
    // startup of the simulated app. Instead the delegate will get a
    // session:started:withError: message after the timeout has elapsed. To
    // account for this case, check if the simulated app's stdio file was
    // ever created and if it exists dump it to stdout and return success.
    NSFileManager* fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath:stdioPath_]) {
      appRunning_ = NO;
      [self tailOutputForSession:session];
      // Note that exiting in this state leaves a process running
      // (e.g. /.../iPhoneSimulator4.3.sdk/usr/libexec/installd -t 30) that will
      // prevent future simulator sessions from being started for 30 seconds
      // unless the iOS Simulator application is killed altogether.
      [self session:session didEndWithError:nil];

      // session:didEndWithError should not return (because it exits) so
      // the execution path should never get here.
      exit(kExitFailure);
    }

    LogError(@"Simulator failed to start: \"%@\" (%@:%ld)",
             [error localizedDescription],
             [error domain], static_cast<long int>([error code]));
    PrintSupportedDevices();
    exit(kExitAppFailedToStart);
  }

  // Start a thread to write contents of outputPath to stdout.
  appRunning_ = YES;
  outputThread_ =
      [[NSThread alloc] initWithTarget:self
                              selector:@selector(tailOutputForSession:)
                                object:session];
  [outputThread_ start];
}

- (void)session:(DTiPhoneSimulatorSession*)session
    didEndWithError:(NSError*)error {
  appRunning_ = NO;
  // Wait for the output thread to finish copying data to stdout.
  if (outputThread_) {
    while (![outputThread_ isFinished]) {
      [NSThread sleepForTimeInterval:kOutputPollIntervalSeconds];
    }
    [outputThread_ release];
    outputThread_ = nil;
  }

  if (error) {
    // There appears to be a race condition where sometimes the simulator
    // framework will end with an error, but the error is that the simulated
    // app cleanly shut down; try to trap this error and don't fail the
    // simulator run.
    NSString* localizedDescription = [error localizedDescription];
    NSString* ignorableErrorStr =
        [self localizedSimulatorErrorString:kSimulatorAppQuitErrorKey];
    if ([ignorableErrorStr isEqual:localizedDescription]) {
      LogWarning(@"Ignoring that Simulator ended with: \"%@\" (%@:%ld)",
                 localizedDescription, [error domain],
                 static_cast<long int>([error code]));
    } else {
      LogError(@"Simulator ended with error: \"%@\" (%@:%ld)",
               localizedDescription, [error domain],
               static_cast<long int>([error code]));
      exit(kExitFailure);
    }
  }

  // Try to determine if the simulated app crashed or quit with a non-zero
  // status code. iOS Simluator handles things a bit differently depending on
  // the version, so first determine the iOS version being used.
  BOOL badEntryFound = NO;

  // The iOS Simulator's system logging is sandboxed, so parse the sandboxed
  // system.log file for known errors.
  NSString* path;
  NSString* dataPath = session.sessionConfig.device.dataPath;
  path =
      [dataPath stringByAppendingPathComponent:@"Library/Logs/system.log"];
  NSFileManager* fileManager = [NSFileManager defaultManager];
  if ([fileManager fileExistsAtPath:path]) {
    NSString* content =
        [NSString stringWithContentsOfFile:path
                                  encoding:NSUTF8StringEncoding
                                     error:NULL];
    NSArray* lines = [content componentsSeparatedByCharactersInSet:
        [NSCharacterSet newlineCharacterSet]];
    NSString* simulatedAppPID =
        [NSString stringWithFormat:@"%d", session.simulatedApplicationPID];
    NSArray* kErrorStrings = @[
      @"Service exited with abnormal code:",
      @"Service exited due to signal:",
    ];
    for (NSString* line in lines) {
      if ([line rangeOfString:simulatedAppPID].location != NSNotFound) {
        for (NSString* errorString in kErrorStrings) {
          if ([line rangeOfString:errorString].location != NSNotFound) {
            LogWarning(@"Console message: %@", line);
            badEntryFound = YES;
            break;
          }
        }
        if (badEntryFound) {
          break;
        }
      }
    }
    // Remove the log file so subsequent invocations of iossim won't be
    // looking at stale logs.
    remove([path fileSystemRepresentation]);
  } else {
      LogWarning(@"Unable to find system log at '%@'.", path);
  }

  // If the query returned any nasty-looking results, iossim should exit with
  // non-zero status.
  if (badEntryFound) {
    LogError(@"Simulated app crashed or exited with non-zero status");
    exit(kExitAppCrashed);
  }
  exit(kExitSuccess);
}
@end

namespace {

// Finds the developer dir via xcode-select or the DEVELOPER_DIR environment
// variable.
NSString* FindDeveloperDir() {
  // Check the env first.
  NSDictionary* env = [[NSProcessInfo processInfo] environment];
  NSString* developerDir = [env objectForKey:@"DEVELOPER_DIR"];
  if ([developerDir length] > 0)
    return developerDir;

  // Go look for it via xcode-select.
  NSString* output = GetOutputFromTask(@"/usr/bin/xcode-select",
                                       @[ @"-print-path" ]);
  output = [output stringByTrimmingCharactersInSet:
      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
  if ([output length] == 0)
    output = nil;
  return output;
}

// Loads the Simulator framework from the given developer dir.
NSBundle* LoadSimulatorFramework(NSString* developerDir) {
  // The Simulator framework depends on some of the other Xcode private
  // frameworks; manually load them first so everything can be linked up.
  NSString* dvtFoundationPath = [developerDir
      stringByAppendingPathComponent:kDVTFoundationRelativePath];
  NSBundle* dvtFoundationBundle =
      [NSBundle bundleWithPath:dvtFoundationPath];
  if (![dvtFoundationBundle load])
    return nil;

  NSString* devToolsFoundationPath = [developerDir
      stringByAppendingPathComponent:kDevToolsFoundationRelativePath];
  NSBundle* devToolsFoundationBundle =
      [NSBundle bundleWithPath:devToolsFoundationPath];
  if (![devToolsFoundationBundle load])
    return nil;

  // Prime DVTPlatform.
  NSError* error;
  Class DVTPlatformClass = FindClassByName(@"DVTPlatform");
  if (![DVTPlatformClass loadAllPlatformsReturningError:&error]) {
    LogError(@"Unable to loadAllPlatformsReturningError. Error: %@",
         [error localizedDescription]);
    return nil;
  }

  // The path within the developer dir of the private Simulator frameworks.
  NSString* simulatorFrameworkRelativePath;
  simulatorFrameworkRelativePath =
      @"../SharedFrameworks/DVTiPhoneSimulatorRemoteClient.framework";
  NSString* const kCoreSimulatorRelativePath =
     @"Library/PrivateFrameworks/CoreSimulator.framework";
  NSString* coreSimulatorPath = [developerDir
      stringByAppendingPathComponent:kCoreSimulatorRelativePath];
  NSBundle* coreSimulatorBundle =
      [NSBundle bundleWithPath:coreSimulatorPath];
  if (![coreSimulatorBundle load])
    return nil;
  NSString* simBundlePath = [developerDir
      stringByAppendingPathComponent:simulatorFrameworkRelativePath];
  NSBundle* simBundle = [NSBundle bundleWithPath:simBundlePath];
  if (![simBundle load])
    return nil;
  return simBundle;
}

// Converts the given app path to an application spec, which requires an
// absolute path.
DTiPhoneSimulatorApplicationSpecifier* BuildAppSpec(NSString* appPath) {
  Class applicationSpecifierClass =
      FindClassByName(@"DTiPhoneSimulatorApplicationSpecifier");
  if (![appPath isAbsolutePath]) {
    NSString* cwd = [[NSFileManager defaultManager] currentDirectoryPath];
    appPath = [cwd stringByAppendingPathComponent:appPath];
  }
  appPath = [appPath stringByStandardizingPath];
  NSFileManager* fileManager = [NSFileManager defaultManager];
  if (![fileManager fileExistsAtPath:appPath]) {
    LogError(@"File not found: %@", appPath);
    exit(kExitInvalidArguments);
  }
  return [applicationSpecifierClass specifierWithApplicationPath:appPath];
}

// Returns the system root for the given SDK version. If sdkVersion is nil, the
// default system root is returned.  Will return nil if the sdkVersion is not
// valid.
DTiPhoneSimulatorSystemRoot* BuildSystemRoot(NSString* sdkVersion) {
  Class systemRootClass = FindClassByName(@"DTiPhoneSimulatorSystemRoot");
  Class simRuntimeClass = FindClassByName(@"SimRuntime");
  NSArray* sorted =
      [[simRuntimeClass supportedRuntimes] sortedArrayUsingDescriptors:@[
        [NSSortDescriptor sortDescriptorWithKey:@"version" ascending:YES]
      ]];
  NSString* versionString = [[sorted lastObject] versionString];
  DTiPhoneSimulatorSystemRoot* systemRoot =
      [systemRootClass rootWithSDKVersion:versionString];
  if (sdkVersion)
    systemRoot = [systemRootClass rootWithSDKVersion:sdkVersion];

  return systemRoot;
}

// Builds a config object for starting the specified app.
DTiPhoneSimulatorSessionConfig* BuildSessionConfig(
    DTiPhoneSimulatorApplicationSpecifier* appSpec,
    DTiPhoneSimulatorSystemRoot* systemRoot,
    NSString* stdoutPath,
    NSString* stderrPath,
    NSArray* appArgs,
    NSDictionary* appEnv,
    NSNumber* deviceFamily,
    NSString* deviceName) {
  Class sessionConfigClass = FindClassByName(@"DTiPhoneSimulatorSessionConfig");
  DTiPhoneSimulatorSessionConfig* sessionConfig =
      [[[sessionConfigClass alloc] init] autorelease];
  sessionConfig.applicationToSimulateOnStart = appSpec;
  sessionConfig.simulatedSystemRoot = systemRoot;
  sessionConfig.localizedClientName = @"chromium";
  sessionConfig.simulatedApplicationStdErrPath = stderrPath;
  sessionConfig.simulatedApplicationStdOutPath = stdoutPath;
  sessionConfig.simulatedApplicationLaunchArgs = appArgs;
  sessionConfig.simulatedApplicationLaunchEnvironment = appEnv;
  sessionConfig.simulatedDeviceInfoName = deviceName;
  sessionConfig.simulatedDeviceFamily = deviceFamily;

  Class simDeviceTypeClass = FindClassByName(@"SimDeviceType");
  id simDeviceType =
      [simDeviceTypeClass supportedDeviceTypesByAlias][deviceName];
  Class simRuntimeClass = FindClassByName(@"SimRuntime");
  NSString* identifier = systemRoot.runtime.identifier;
  id simRuntime = [simRuntimeClass supportedRuntimesByIdentifier][identifier];

  // Attempt to use an existing device, but create one if a suitable match
  // can't be found. For example, if the simulator is running with a
  // non-default home directory (e.g. via iossim's -u command line arg) then
  // there won't be any devices so one will have to be created.
  Class simDeviceSetClass = FindClassByName(@"SimDeviceSet");
  id deviceSet =
      [simDeviceSetClass setForSetPath:[simDeviceSetClass defaultSetPath]];
  id simDevice = nil;
  for (id device in [deviceSet availableDevices]) {
    if ([device runtime] == simRuntime &&
        [device deviceType] == simDeviceType) {
      simDevice = device;
      break;
    }
  }
  if (!simDevice) {
    NSError* error = nil;
    // n.b. only the device name is necessary because the iOS Simulator menu
    // already splits devices by runtime version.
    NSString* name = [NSString stringWithFormat:@"iossim - %@ ", deviceName];
    simDevice = [deviceSet createDeviceWithType:simDeviceType
                                        runtime:simRuntime
                                           name:name
                                          error:&error];
    if (error) {
      LogError(@"Failed to create device: %@", error);
      exit(kExitInitializationFailure);
    }
  }
  sessionConfig.device = simDevice;
  return sessionConfig;
}

// Builds a simulator session that will use the given delegate.
DTiPhoneSimulatorSession* BuildSession(SimulatorDelegate* delegate) {
  Class sessionClass = FindClassByName(@"DTiPhoneSimulatorSession");
  DTiPhoneSimulatorSession* session =
      [[[sessionClass alloc] init] autorelease];
  session.delegate = delegate;
  return session;
}

// Creates a temporary directory with a unique name based on the provided
// template. The template should not contain any path separators and be suffixed
// with X's, which will be substituted with a unique alphanumeric string (see
// 'man mkdtemp' for details). The directory will be created as a subdirectory
// of NSTemporaryDirectory(). For example, if dirNameTemplate is 'test-XXX',
// this method would return something like '/path/to/tempdir/test-3n2'.
//
// Returns the absolute path of the newly-created directory, or nill if unable
// to create a unique directory.
NSString* CreateTempDirectory(NSString* dirNameTemplate) {
  NSString* fullPathTemplate =
      [NSTemporaryDirectory() stringByAppendingPathComponent:dirNameTemplate];
  char* fullPath = mkdtemp(const_cast<char*>([fullPathTemplate UTF8String]));
  if (fullPath == NULL)
    return nil;

  return [NSString stringWithUTF8String:fullPath];
}

// Creates the necessary directory structure under the given user home directory
// path.
// Returns YES if successful, NO if unable to create the directories.
BOOL CreateHomeDirSubDirs(NSString* userHomePath) {
  NSFileManager* fileManager = [NSFileManager defaultManager];

  // Create user home and subdirectories.
  NSArray* subDirsToCreate = [NSArray arrayWithObjects:
                              @"Documents",
                              @"Library/Caches",
                              @"Library/Preferences",
                              nil];
  for (NSString* subDir in subDirsToCreate) {
    NSString* path = [userHomePath stringByAppendingPathComponent:subDir];
    NSError* error;
    if (![fileManager createDirectoryAtPath:path
                withIntermediateDirectories:YES
                                 attributes:nil
                                      error:&error]) {
      LogError(@"Unable to create directory: %@. Error: %@",
               path, [error localizedDescription]);
      return NO;
    }
  }

  return YES;
}

// Creates the necessary directory structure under the given user home directory
// path, then sets the path in the appropriate environment variable.
// Returns YES if successful, NO if unable to create or initialize the given
// directory.
BOOL InitializeSimulatorUserHome(NSString* userHomePath) {
  if (!CreateHomeDirSubDirs(userHomePath))
    return NO;

  // Update the environment to use the specified directory as the user home
  // directory.
  // Note: the third param of setenv specifies whether or not to overwrite the
  // variable's value if it has already been set.
  if ((setenv(kUserHomeEnvVariable, [userHomePath UTF8String], YES) == -1) ||
      (setenv(kHomeEnvVariable, [userHomePath UTF8String], YES) == -1)) {
    LogError(@"Unable to set environment variables for home directory.");
    return NO;
  }

  return YES;
}

// Prints the usage information to stderr.
void PrintUsage() {
  fprintf(stderr, "Usage: iossim [-d device] [-s sdkVersion] [-u homeDir] "
      "[-e envKey=value]* [-t startupTimeout] <appPath> [<appArgs>]\n"
      "  where <appPath> is the path to the .app directory and appArgs are any"
      " arguments to send the simulated app.\n"
      "\n"
      "Options:\n"
      "  -d  Specifies the device (must be one of the values from the iOS"
      " Simulator's Hardware -> Device menu. Defaults to 'iPhone'.\n"
      "  -s  Specifies the SDK version to use (e.g '4.3')."
      " Will use system default if not specified.\n"
      "  -u  Specifies a user home directory for the simulator."
      " Will create a new directory if not specified.\n"
      "  -e  Specifies an environment key=value pair that will be"
      " set in the simulated application's environment.\n"
      "  -t  Specifies the session startup timeout (in seconds)."
      " Defaults to %d.\n"
      "  -l  List supported devices and iOS versions.\n",
      static_cast<int>(kDefaultSessionStartTimeoutSeconds));
}
}  // namespace

int main(int argc, char* const argv[]) {
  NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];

  // basename() may modify the passed in string and it returns a pointer to an
  // internal buffer. Give it a copy to modify, and copy what it returns.
  char* worker = strdup(argv[0]);
  char* toolName = basename(worker);
  if (toolName != NULL) {
    toolName = strdup(toolName);
    if (toolName != NULL)
      gToolName = toolName;
  }
  if (worker != NULL)
    free(worker);

  NSString* appPath = nil;
  NSString* appName = nil;
  NSString* sdkVersion = nil;
  NSString* deviceName = @"iPhone 5s";
  NSString* simHomePath = nil;
  NSMutableArray* appArgs = [NSMutableArray array];
  NSMutableDictionary* appEnv = [NSMutableDictionary dictionary];
  NSTimeInterval sessionStartTimeout = kDefaultSessionStartTimeoutSeconds;

  NSString* developerDir = FindDeveloperDir();
  if (!developerDir) {
    LogError(@"Unable to find developer directory.");
    exit(kExitInitializationFailure);
  }

  NSBundle* simulatorFramework = LoadSimulatorFramework(developerDir);
  if (!simulatorFramework) {
    LogError(@"Failed to load the Simulator Framework.");
    exit(kExitInitializationFailure);
  }

  // Parse the optional arguments
  int c;
  while ((c = getopt(argc, argv, "hs:d:u:e:t:l")) != -1) {
    switch (c) {
      case 's':
        sdkVersion = [NSString stringWithUTF8String:optarg];
        break;
      case 'd':
        deviceName = [NSString stringWithUTF8String:optarg];
        break;
      case 'u':
        simHomePath = [[NSFileManager defaultManager]
            stringWithFileSystemRepresentation:optarg length:strlen(optarg)];
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
        [appEnv setObject:value forKey:key];
      }
        break;
      case 't': {
        int timeout = atoi(optarg);
        if (timeout > 0) {
          sessionStartTimeout = static_cast<NSTimeInterval>(timeout);
        } else {
          LogError(@"Invalid startup timeout (%s).", optarg);
          PrintUsage();
          exit(kExitInvalidArguments);
        }
      }
        break;
      case 'l':
        PrintSupportedDevices();
        exit(kExitSuccess);
        break;
      case 'h':
        PrintUsage();
        exit(kExitSuccess);
      default:
        PrintUsage();
        exit(kExitInvalidArguments);
    }
  }

  // There should be at least one arg left, specifying the app path. Any
  // additional args are passed as arguments to the app.
  if (optind < argc) {
    appPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:argv[optind]
                                    length:strlen(argv[optind])];
    appName = [appPath lastPathComponent];
    while (++optind < argc) {
      [appArgs addObject:[NSString stringWithUTF8String:argv[optind]]];
    }
  } else {
    LogError(@"Unable to parse command line arguments.");
    PrintUsage();
    exit(kExitInvalidArguments);
  }

  // Make sure the app path provided is legit.
  DTiPhoneSimulatorApplicationSpecifier* appSpec = BuildAppSpec(appPath);
  if (!appSpec) {
    LogError(@"Invalid app path: %@", appPath);
    exit(kExitInitializationFailure);
  }

  // Make sure the SDK path provided is legit (or nil).
  DTiPhoneSimulatorSystemRoot* systemRoot = BuildSystemRoot(sdkVersion);
  if (!systemRoot) {
    LogError(@"Invalid SDK version: %@", sdkVersion);
    PrintSupportedDevices();
    exit(kExitInitializationFailure);
  }

  // Get the paths for stdout and stderr so the simulated app's output will show
  // up in the caller's stdout/stderr.
  NSString* outputDir = CreateTempDirectory(@"iossim-XXXXXX");
  NSString* stdioPath = [outputDir stringByAppendingPathComponent:@"stdio.txt"];

  // Determine the deviceFamily based on the deviceName
  NSNumber* deviceFamily = nil;
  Class simDeviceTypeClass = FindClassByName(@"SimDeviceType");
  if ([simDeviceTypeClass supportedDeviceTypesByAlias][deviceName] == nil) {
    LogError(@"Invalid device name: %@.", deviceName);
    PrintSupportedDevices();
    exit(kExitInvalidArguments);
  }

  // Set up the user home directory for the simulator only if a non-default
  // value was specified.
  if (simHomePath) {
    if (!InitializeSimulatorUserHome(simHomePath)) {
      LogError(@"Unable to initialize home directory for simulator: %@",
               simHomePath);
      exit(kExitInitializationFailure);
    }
  } else {
    simHomePath = NSHomeDirectory();
  }

  // Create the config and simulator session.
  DTiPhoneSimulatorSessionConfig* config = BuildSessionConfig(appSpec,
                                                              systemRoot,
                                                              stdioPath,
                                                              stdioPath,
                                                              appArgs,
                                                              appEnv,
                                                              deviceFamily,
                                                              deviceName);
  SimulatorDelegate* delegate =
      [[[SimulatorDelegate alloc] initWithStdioPath:stdioPath
                                       developerDir:developerDir
                                      simulatorHome:simHomePath] autorelease];
  DTiPhoneSimulatorSession* session = BuildSession(delegate);

  // Start the simulator session.
  NSError* error;
  BOOL started = [session requestStartWithConfig:config
                                         timeout:sessionStartTimeout
                                           error:&error];

  // Spin the runtime indefinitely. When the delegate gets the message that the
  // app has quit it will exit this program.
  if (started) {
    [[NSRunLoop mainRunLoop] run];
  } else {
    LogError(@"Simulator failed request to start:  \"%@\" (%@:%ld)",
             [error localizedDescription],
             [error domain], static_cast<long int>([error code]));
  }

  // Note that this code is only executed if the simulator fails to start
  // because once the main run loop is started, only the delegate calling
  // exit() will end the program.
  [pool drain];
  return kExitFailure;
}

#endif

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_config_service_linux.h"

#include <map>
#include <string>
#include <vector>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/format_macros.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/proxy/proxy_config.h"
#include "net/proxy/proxy_config_service_common_unittest.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace net {
namespace {

// Set of values for all environment variables that we might
// query. NULL represents an unset variable.
struct EnvVarValues {
  // The strange capitalization is so that the field matches the
  // environment variable name exactly.
  const char* DESKTOP_SESSION;
  const char* HOME;
  const char* KDEHOME;
  const char* KDE_SESSION_VERSION;
  const char* XDG_CURRENT_DESKTOP;
  const char* auto_proxy;
  const char* all_proxy;
  const char* http_proxy;
  const char* https_proxy;
  const char* ftp_proxy;
  const char* SOCKS_SERVER;
  const char* SOCKS_VERSION;
  const char* no_proxy;
};

// Undo macro pollution from GDK includes (from message_loop.h).
#undef TRUE
#undef FALSE

// So as to distinguish between an unset gconf boolean variable and
// one that is false.
enum BoolSettingValue {
  UNSET = 0, TRUE, FALSE
};

// Set of values for all gconf settings that we might query.
struct GConfValues {
  // strings
  const char* mode;
  const char* autoconfig_url;
  const char* http_host;
  const char* secure_host;
  const char* ftp_host;
  const char* socks_host;
  // integers
  int http_port;
  int secure_port;
  int ftp_port;
  int socks_port;
  // booleans
  BoolSettingValue use_proxy;
  BoolSettingValue same_proxy;
  BoolSettingValue use_auth;
  // string list
  std::vector<std::string> ignore_hosts;
};

// Mapping from a setting name to the location of the corresponding
// value (inside a EnvVarValues or GConfValues struct).
template<typename key_type, typename value_type>
struct SettingsTable {
  typedef std::map<key_type, value_type*> map_type;

  // Gets the value from its location
  value_type Get(key_type key) {
    auto it = settings.find(key);
    // In case there's a typo or the unittest becomes out of sync.
    CHECK(it != settings.end()) << "key " << key << " not found";
    value_type* value_ptr = it->second;
    return *value_ptr;
  }

  map_type settings;
};

class MockEnvironment : public base::Environment {
 public:
  MockEnvironment() {
#define ENTRY(x) table_[#x] = &values.x
    ENTRY(DESKTOP_SESSION);
    ENTRY(HOME);
    ENTRY(KDEHOME);
    ENTRY(KDE_SESSION_VERSION);
    ENTRY(XDG_CURRENT_DESKTOP);
    ENTRY(auto_proxy);
    ENTRY(all_proxy);
    ENTRY(http_proxy);
    ENTRY(https_proxy);
    ENTRY(ftp_proxy);
    ENTRY(no_proxy);
    ENTRY(SOCKS_SERVER);
    ENTRY(SOCKS_VERSION);
#undef ENTRY
    Reset();
  }

  // Zeroes all environment values.
  void Reset() {
    EnvVarValues zero_values = { 0 };
    values = zero_values;
  }

  // Begin base::Environment implementation.
  bool GetVar(base::StringPiece variable_name, std::string* result) override {
    auto it = table_.find(variable_name);
    if (it == table_.end() || !*it->second)
      return false;

    // Note that the variable may be defined but empty.
    *result = *(it->second);
    return true;
  }

  bool SetVar(base::StringPiece variable_name,
              const std::string& new_value) override {
    ADD_FAILURE();
    return false;
  }

  bool UnSetVar(base::StringPiece variable_name) override {
    ADD_FAILURE();
    return false;
  }
  // End base::Environment implementation.

  // Intentionally public, for convenience when setting up a test.
  EnvVarValues values;

 private:
  std::map<base::StringPiece, const char**> table_;
};

class MockSettingGetter
    : public ProxyConfigServiceLinux::SettingGetter {
 public:
  typedef ProxyConfigServiceLinux::SettingGetter SettingGetter;
  MockSettingGetter() {
#define ENTRY(key, field) \
      strings_table.settings[SettingGetter::key] = &values.field
    ENTRY(PROXY_MODE, mode);
    ENTRY(PROXY_AUTOCONF_URL, autoconfig_url);
    ENTRY(PROXY_HTTP_HOST, http_host);
    ENTRY(PROXY_HTTPS_HOST, secure_host);
    ENTRY(PROXY_FTP_HOST, ftp_host);
    ENTRY(PROXY_SOCKS_HOST, socks_host);
#undef ENTRY
#define ENTRY(key, field) \
      ints_table.settings[SettingGetter::key] = &values.field
    ENTRY(PROXY_HTTP_PORT, http_port);
    ENTRY(PROXY_HTTPS_PORT, secure_port);
    ENTRY(PROXY_FTP_PORT, ftp_port);
    ENTRY(PROXY_SOCKS_PORT, socks_port);
#undef ENTRY
#define ENTRY(key, field) \
      bools_table.settings[SettingGetter::key] = &values.field
    ENTRY(PROXY_USE_HTTP_PROXY, use_proxy);
    ENTRY(PROXY_USE_SAME_PROXY, same_proxy);
    ENTRY(PROXY_USE_AUTHENTICATION, use_auth);
#undef ENTRY
    string_lists_table.settings[SettingGetter::PROXY_IGNORE_HOSTS] =
        &values.ignore_hosts;
    Reset();
  }

  // Zeros all environment values.
  void Reset() {
    GConfValues zero_values = { 0 };
    values = zero_values;
  }

  bool Init(const scoped_refptr<base::SingleThreadTaskRunner>& glib_task_runner,
            const scoped_refptr<base::SingleThreadTaskRunner>& file_task_runner)
      override {
    task_runner_ = glib_task_runner;
    return true;
  }

  void ShutDown() override {}

  bool SetUpNotifications(
      ProxyConfigServiceLinux::Delegate* delegate) override {
    return true;
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& GetNotificationTaskRunner()
      override {
    return task_runner_;
  }

  ProxyConfigSource GetConfigSource() override {
    return PROXY_CONFIG_SOURCE_TEST;
  }

  bool GetString(StringSetting key, std::string* result) override {
    const char* value = strings_table.Get(key);
    if (value) {
      *result = value;
      return true;
    }
    return false;
  }

  bool GetBool(BoolSetting key, bool* result) override {
    BoolSettingValue value = bools_table.Get(key);
    switch (value) {
    case UNSET:
      return false;
    case TRUE:
      *result = true;
      break;
    case FALSE:
      *result = false;
    }
    return true;
  }

  bool GetInt(IntSetting key, int* result) override {
    // We don't bother to distinguish unset keys from 0 values.
    *result = ints_table.Get(key);
    return true;
  }

  bool GetStringList(StringListSetting key,
                     std::vector<std::string>* result) override {
    *result = string_lists_table.Get(key);
    // We don't bother to distinguish unset keys from empty lists.
    return !result->empty();
  }

  bool BypassListIsReversed() override { return false; }

  bool MatchHostsUsingSuffixMatching() override { return false; }

  // Intentionally public, for convenience when setting up a test.
  GConfValues values;

 private:
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  SettingsTable<StringSetting, const char*> strings_table;
  SettingsTable<BoolSetting, BoolSettingValue> bools_table;
  SettingsTable<IntSetting, int> ints_table;
  SettingsTable<StringListSetting,
                std::vector<std::string> > string_lists_table;
};

// This helper class runs ProxyConfigServiceLinux::GetLatestProxyConfig() on
// the IO thread and synchronously waits for the result.
// Some code duplicated from proxy_script_fetcher_unittest.cc.
class SynchConfigGetter {
 public:
  // Takes ownership of |config_service|.
  explicit SynchConfigGetter(ProxyConfigServiceLinux* config_service)
      : event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
               base::WaitableEvent::InitialState::NOT_SIGNALED),
        io_thread_("IO_Thread"),
        config_service_(config_service) {
    // Start an IO thread.
    base::Thread::Options options;
    options.message_loop_type = base::MessageLoop::TYPE_IO;
    io_thread_.StartWithOptions(options);

    // Make sure the thread started.
    io_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&SynchConfigGetter::Init, base::Unretained(this)));
    Wait();
  }

  ~SynchConfigGetter() {
    // Let the config service post a destroy message to the IO thread
    // before cleaning up that thread.
    delete config_service_;
    // Clean up the IO thread.
    io_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&SynchConfigGetter::CleanUp, base::Unretained(this)));
    Wait();
  }

  // Does gconf setup and initial fetch of the proxy config,
  // all on the calling thread (meant to be the thread with the
  // default glib main loop, which is the UI thread).
  void SetupAndInitialFetch() {
    // We pass the mock IO thread as both the IO and file threads.
    config_service_->SetupAndFetchInitialConfig(
        base::ThreadTaskRunnerHandle::Get(), io_thread_.task_runner(),
        io_thread_.task_runner());
  }
  // Synchronously gets the proxy config.
  ProxyConfigService::ConfigAvailability SyncGetLatestProxyConfig(
      ProxyConfig* config) {
    io_thread_.task_runner()->PostTask(
        FROM_HERE, base::Bind(&SynchConfigGetter::GetLatestConfigOnIOThread,
                              base::Unretained(this)));
    Wait();
    *config = proxy_config_;
    return get_latest_config_result_;
  }

 private:
  // [Runs on |io_thread_|]
  void Init() {
    event_.Signal();
  }

  // Calls GetLatestProxyConfig, running on |io_thread_| Signals |event_|
  // on completion.
  void GetLatestConfigOnIOThread() {
    get_latest_config_result_ =
        config_service_->GetLatestProxyConfig(&proxy_config_);
    event_.Signal();
  }

  // [Runs on |io_thread_|] Signals |event_| on cleanup completion.
  void CleanUp() {
    base::RunLoop().RunUntilIdle();
    event_.Signal();
  }

  void Wait() {
    event_.Wait();
    event_.Reset();
  }

  base::WaitableEvent event_;
  base::Thread io_thread_;

  ProxyConfigServiceLinux* config_service_;

  // The config obtained by |io_thread_| and read back by the main
  // thread.
  ProxyConfig proxy_config_;

  // Return value from GetLatestProxyConfig().
  ProxyConfigService::ConfigAvailability get_latest_config_result_;
};

// This test fixture is only really needed for the KDEConfigParser test case,
// but all the test cases with the same prefix ("ProxyConfigServiceLinuxTest")
// must use the same test fixture class (also "ProxyConfigServiceLinuxTest").
class ProxyConfigServiceLinuxTest : public PlatformTest {
 protected:
  void SetUp() override {
    PlatformTest::SetUp();
    // Set up a temporary KDE home directory.
    std::string prefix("ProxyConfigServiceLinuxTest_user_home");
    base::CreateNewTempDirectory(prefix, &user_home_);
    config_home_ = user_home_.Append(FILE_PATH_LITERAL(".config"));
    kde_home_ = user_home_.Append(FILE_PATH_LITERAL(".kde"));
    base::FilePath path = kde_home_.Append(FILE_PATH_LITERAL("share"));
    path = path.Append(FILE_PATH_LITERAL("config"));
    base::CreateDirectory(path);
    kioslaverc_ = path.Append(FILE_PATH_LITERAL("kioslaverc"));
    // Set up paths but do not create the directory for .kde4.
    kde4_home_ = user_home_.Append(FILE_PATH_LITERAL(".kde4"));
    path = kde4_home_.Append(FILE_PATH_LITERAL("share"));
    kde4_config_ = path.Append(FILE_PATH_LITERAL("config"));
    kioslaverc4_ = kde4_config_.Append(FILE_PATH_LITERAL("kioslaverc"));
    // Set up paths for KDE 5
    kioslaverc5_ = config_home_.Append(FILE_PATH_LITERAL("kioslaverc"));
  }

  void TearDown() override {
    // Delete the temporary KDE home directory.
    base::DeleteFile(user_home_, true);
    PlatformTest::TearDown();
  }

  base::FilePath user_home_;
  base::FilePath config_home_;
  // KDE3 paths.
  base::FilePath kde_home_;
  base::FilePath kioslaverc_;
  // KDE4 paths.
  base::FilePath kde4_home_;
  base::FilePath kde4_config_;
  base::FilePath kioslaverc4_;
  // KDE5 paths.
  base::FilePath kioslaverc5_;
};

// Builds an identifier for each test in an array.
#define TEST_DESC(desc) base::StringPrintf("at line %d <%s>", __LINE__, desc)

TEST_F(ProxyConfigServiceLinuxTest, BasicGConfTest) {
  std::vector<std::string> empty_ignores;

  std::vector<std::string> google_ignores;
  google_ignores.push_back("*.google.com");

  // Inspired from proxy_config_service_win_unittest.cc.
  // Very neat, but harder to track down failures though.
  const struct {
    // Short description to identify the test
    std::string description;

    // Input.
    GConfValues values;

    // Expected outputs (availability and fields of ProxyConfig).
    ProxyConfigService::ConfigAvailability availability;
    bool auto_detect;
    GURL pac_url;
    ProxyRulesExpectation proxy_rules;
  } tests[] = {
    {
      TEST_DESC("No proxying"),
      { // Input.
        "none",                   // mode
        "",                       // autoconfig_url
        "", "", "", "",           // hosts
        0, 0, 0, 0,               // ports
        FALSE, FALSE, FALSE,      // use, same, auth
        empty_ignores,            // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                      // auto_detect
      GURL(),                     // pac_url
      ProxyRulesExpectation::Empty(),
    },

    {
      TEST_DESC("Auto detect"),
      { // Input.
        "auto",                   // mode
        "",                       // autoconfig_url
        "", "", "", "",           // hosts
        0, 0, 0, 0,               // ports
        FALSE, FALSE, FALSE,      // use, same, auth
        empty_ignores,            // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      true,                       // auto_detect
      GURL(),                     // pac_url
      ProxyRulesExpectation::Empty(),
    },

    {
      TEST_DESC("Valid PAC URL"),
      { // Input.
        "auto",                      // mode
        "http://wpad/wpad.dat",      // autoconfig_url
        "", "", "", "",              // hosts
        0, 0, 0, 0,                  // ports
        FALSE, FALSE, FALSE,         // use, same, auth
        empty_ignores,               // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                         // auto_detect
      GURL("http://wpad/wpad.dat"),  // pac_url
      ProxyRulesExpectation::Empty(),
    },

    {
      TEST_DESC("Invalid PAC URL"),
      { // Input.
        "auto",                      // mode
        "wpad.dat",                  // autoconfig_url
        "", "", "", "",              // hosts
        0, 0, 0, 0,                  // ports
        FALSE, FALSE, FALSE,         // use, same, auth
        empty_ignores,               // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                          // auto_detect
      GURL(),                        // pac_url
      ProxyRulesExpectation::Empty(),
    },

    {
      TEST_DESC("Single-host in proxy list"),
      { // Input.
        "manual",                              // mode
        "",                                    // autoconfig_url
        "www.google.com", "", "", "",          // hosts
        80, 0, 0, 0,                           // ports
        TRUE, TRUE, FALSE,                     // use, same, auth
        empty_ignores,                         // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                   // auto_detect
      GURL(),                                  // pac_url
      ProxyRulesExpectation::Single(
          "www.google.com:80",  // single proxy
          ""),                  // bypass rules
    },

    {
      TEST_DESC("use_http_proxy is honored"),
      { // Input.
        "manual",                              // mode
        "",                                    // autoconfig_url
        "www.google.com", "", "", "",          // hosts
        80, 0, 0, 0,                           // ports
        FALSE, TRUE, FALSE,                    // use, same, auth
        empty_ignores,                         // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                   // auto_detect
      GURL(),                                  // pac_url
      ProxyRulesExpectation::Empty(),
    },

    {
      TEST_DESC("use_http_proxy and use_same_proxy are optional"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "www.google.com", "", "", "",                 // hosts
        80, 0, 0, 0,                                  // ports
        UNSET, UNSET, FALSE,                          // use, same, auth
        empty_ignores,                                // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::PerScheme(
          "www.google.com:80",  // http
          "",                   // https
          "",                   // ftp
          ""),                  // bypass rules
    },

    {
      TEST_DESC("Single-host, different port"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "www.google.com", "", "", "",                 // hosts
        88, 0, 0, 0,                                  // ports
        TRUE, TRUE, FALSE,                            // use, same, auth
        empty_ignores,                                // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::Single(
          "www.google.com:88",  // single proxy
          ""),                  // bypass rules
    },

    {
      TEST_DESC("Per-scheme proxy rules"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "www.google.com",                             // http_host
        "www.foo.com",                                // secure_host
        "ftp.foo.com",                                // ftp
        "",                                           // socks
        88, 110, 121, 0,                              // ports
        TRUE, FALSE, FALSE,                           // use, same, auth
        empty_ignores,                                // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::PerScheme(
          "www.google.com:88",  // http
          "www.foo.com:110",    // https
          "ftp.foo.com:121",    // ftp
          ""),                  // bypass rules
    },

    {
      TEST_DESC("socks"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "", "", "", "socks.com",                      // hosts
        0, 0, 0, 99,                                  // ports
        TRUE, FALSE, FALSE,                           // use, same, auth
        empty_ignores,                                // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::Single(
          "socks5://socks.com:99",  // single proxy
          "")                       // bypass rules
    },

    {
      TEST_DESC("Per-scheme proxy rules with fallback to SOCKS"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "www.google.com",                             // http_host
        "www.foo.com",                                // secure_host
        "ftp.foo.com",                                // ftp
        "foobar.net",                                 // socks
        88, 110, 121, 99,                             // ports
        TRUE, FALSE, FALSE,                           // use, same, auth
        empty_ignores,                                // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::PerSchemeWithSocks(
          "www.google.com:88",      // http
          "www.foo.com:110",        // https
          "ftp.foo.com:121",        // ftp
          "socks5://foobar.net:99", // socks
          ""),                      // bypass rules
    },

    {
      TEST_DESC("Per-scheme proxy rules (just HTTP) with fallback to SOCKS"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "www.google.com",                             // http_host
        "",                                           // secure_host
        "",                                           // ftp
        "foobar.net",                                 // socks
        88, 0, 0, 99,                                 // ports
        TRUE, FALSE, FALSE,                           // use, same, auth
        empty_ignores,                                // ignore_hosts
      },

      // Expected result.
      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::PerSchemeWithSocks(
          "www.google.com:88",      // http
          "",                       // https
          "",                       // ftp
          "socks5://foobar.net:99", // socks
          ""),                      // bypass rules
    },

    {
      TEST_DESC("Bypass *.google.com"),
      { // Input.
        "manual",                                     // mode
        "",                                           // autoconfig_url
        "www.google.com", "", "", "",                 // hosts
        80, 0, 0, 0,                                  // ports
        TRUE, TRUE, FALSE,                            // use, same, auth
        google_ignores,                               // ignore_hosts
      },

      ProxyConfigService::CONFIG_VALID,
      false,                                          // auto_detect
      GURL(),                                         // pac_url
      ProxyRulesExpectation::Single(
          "www.google.com:80",   // single proxy
          "*.google.com"),       // bypass rules
    },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "] %s", i,
                                    tests[i].description.c_str()));
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    MockSettingGetter* setting_getter = new MockSettingGetter;
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env), setting_getter));
    ProxyConfig config;
    setting_getter->values = tests[i].values;
    sync_config_getter.SetupAndInitialFetch();
    ProxyConfigService::ConfigAvailability availability =
        sync_config_getter.SyncGetLatestProxyConfig(&config);
    EXPECT_EQ(tests[i].availability, availability);

    if (availability == ProxyConfigService::CONFIG_VALID) {
      EXPECT_EQ(tests[i].auto_detect, config.auto_detect());
      EXPECT_EQ(tests[i].pac_url, config.pac_url());
      EXPECT_TRUE(tests[i].proxy_rules.Matches(config.proxy_rules()));
    }
  }
}

TEST_F(ProxyConfigServiceLinuxTest, BasicEnvTest) {
  // Inspired from proxy_config_service_win_unittest.cc.
  const struct {
    // Short description to identify the test
    std::string description;

    // Input.
    EnvVarValues values;

    // Expected outputs (availability and fields of ProxyConfig).
    ProxyConfigService::ConfigAvailability availability;
    bool auto_detect;
    GURL pac_url;
    ProxyRulesExpectation proxy_rules;
  } tests[] = {
      {
          TEST_DESC("No proxying"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              "*",                        // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Auto detect"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              "",                         // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          true,    // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC URL"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              "http://wpad/wpad.dat",     // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                         // auto_detect
          GURL("http://wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Invalid PAC URL"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              "wpad.dat",                 // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Single-host in proxy list"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "www.google.com",           // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:80",  // single proxy
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Single-host, different port"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "www.google.com:99",        // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:99",  // single
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Tolerate a scheme"),
          {
              // Input.
              nullptr,                     // DESKTOP_SESSION
              nullptr,                     // HOME
              nullptr,                     // KDEHOME
              nullptr,                     // KDE_SESSION_VERSION
              nullptr,                     // XDG_CURRENT_DESKTOP
              nullptr,                     // auto_proxy
              "http://www.google.com:99",  // all_proxy
              nullptr, nullptr, nullptr,   // per-proto proxies
              nullptr, nullptr,            // SOCKS
              nullptr,                     // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:99",  // single proxy
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Per-scheme proxy rules"),
          {
              // Input.
              nullptr,  // DESKTOP_SESSION
              nullptr,  // HOME
              nullptr,  // KDEHOME
              nullptr,  // KDE_SESSION_VERSION
              nullptr,  // XDG_CURRENT_DESKTOP
              nullptr,  // auto_proxy
              nullptr,  // all_proxy
              "www.google.com:80", "www.foo.com:110",
              "ftp.foo.com:121",  // per-proto
              nullptr, nullptr,   // SOCKS
              nullptr,            // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "www.foo.com:110",    // https
                                           "ftp.foo.com:121",    // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("socks"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "",                         // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              "socks.com:888", nullptr,   // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("socks4"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "",                         // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              "socks.com:888", "4",       // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks4://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("socks default port"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "",                         // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              "socks.com", nullptr,       // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:1080",  // single proxy
              ""),                        // bypass rules
      },

      {
          TEST_DESC("bypass"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "www.google.com",           // all_proxy
              nullptr, nullptr, nullptr,  // per-proto
              nullptr, nullptr,           // SOCKS
              ".google.com, foo.com:99, 1.2.3.4:22, 127.0.0.1/8",  // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "www.google.com:80",
              "*.google.com,*foo.com:99,1.2.3.4:22,127.0.0.1/8"),
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "] %s", i,
                                    tests[i].description.c_str()));
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values = tests[i].values;
    MockSettingGetter* setting_getter = new MockSettingGetter;
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env), setting_getter));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    ProxyConfigService::ConfigAvailability availability =
        sync_config_getter.SyncGetLatestProxyConfig(&config);
    EXPECT_EQ(tests[i].availability, availability);

    if (availability == ProxyConfigService::CONFIG_VALID) {
      EXPECT_EQ(tests[i].auto_detect, config.auto_detect());
      EXPECT_EQ(tests[i].pac_url, config.pac_url());
      EXPECT_TRUE(tests[i].proxy_rules.Matches(config.proxy_rules()));
    }
  }
}

TEST_F(ProxyConfigServiceLinuxTest, GconfNotification) {
  std::unique_ptr<MockEnvironment> env(new MockEnvironment);
  MockSettingGetter* setting_getter = new MockSettingGetter;
  ProxyConfigServiceLinux* service =
      new ProxyConfigServiceLinux(std::move(env), setting_getter);
  SynchConfigGetter sync_config_getter(service);
  ProxyConfig config;

  // Start with no proxy.
  setting_getter->values.mode = "none";
  sync_config_getter.SetupAndInitialFetch();
  EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
            sync_config_getter.SyncGetLatestProxyConfig(&config));
  EXPECT_FALSE(config.auto_detect());

  // Now set to auto-detect.
  setting_getter->values.mode = "auto";
  // Simulate setting change notification callback.
  service->OnCheckProxyConfigSettings();
  EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
            sync_config_getter.SyncGetLatestProxyConfig(&config));
  EXPECT_TRUE(config.auto_detect());
}

TEST_F(ProxyConfigServiceLinuxTest, KDEConfigParser) {
  // One of the tests below needs a worst-case long line prefix. We build it
  // programmatically so that it will always be the right size.
  std::string long_line;
  size_t limit = ProxyConfigServiceLinux::SettingGetter::BUFFER_SIZE - 1;
  for (size_t i = 0; i < limit; ++i)
    long_line += "-";

  // Inspired from proxy_config_service_win_unittest.cc.
  const struct {
    // Short description to identify the test
    std::string description;

    // Input.
    std::string kioslaverc;
    EnvVarValues env_values;

    // Expected outputs (availability and fields of ProxyConfig).
    ProxyConfigService::ConfigAvailability availability;
    bool auto_detect;
    GURL pac_url;
    ProxyRulesExpectation proxy_rules;
  } tests[] = {
      {
          TEST_DESC("No proxying"),

          // Input.
          "[Proxy Settings]\nProxyType=0\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Auto detect"),

          // Input.
          "[Proxy Settings]\nProxyType=3\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          true,    // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC URL"),

          // Input.
          "[Proxy Settings]\nProxyType=2\n"
          "Proxy Config Script=http://wpad/wpad.dat\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                         // auto_detect
          GURL("http://wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC file without file://"),

          // Input.
          "[Proxy Settings]\nProxyType=2\n"
          "Proxy Config Script=/wpad/wpad.dat\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                          // auto_detect
          GURL("file:///wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Per-scheme proxy rules"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "httpsProxy=www.foo.com\nftpProxy=ftp.foo.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "www.foo.com:80",     // https
                                           "ftp.foo.com:80",     // http
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Only HTTP proxy specified"),

          // Input.
          "[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Only HTTP proxy specified, different port"),

          // Input.
          "[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com:88\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:88",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC(
              "Only HTTP proxy specified, different port, space-delimited"),

          // Input.
          "[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com 88\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:88",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Bypass *.google.com"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Bypass *.google.com and *.kde.org"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com,.kde.org\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerScheme(
              "www.google.com:80",        // http
              "",                         // https
              "",                         // ftp
              "*.google.com,*.kde.org"),  // bypass rules
      },

      {
          TEST_DESC("Correctly parse bypass list with ReversedException"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=true\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithBypassReversed(
              "www.google.com:80",  // http
              "",                   // https
              "",                   // ftp
              "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("socks"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nsocksProxy=socks.com 888\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("socks4"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nsocksProxy=socks4://socks.com 888\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks4://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("Treat all hostname patterns as wildcard patterns"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=google.com,kde.org,<local>\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerScheme(
              "www.google.com:80",              // http
              "",                               // https
              "",                               // ftp
              "*google.com,*kde.org,<local>"),  // bypass rules
      },

      {
          TEST_DESC("Allow trailing whitespace after boolean value"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=true  \n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithBypassReversed(
              "www.google.com:80",  // http
              "",                   // https
              "",                   // ftp
              "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Ignore settings outside [Proxy Settings]"),

          // Input.
          "httpsProxy=www.foo.com\n[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com\n[Other Section]\nftpProxy=ftp.foo.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Handle CRLF line endings"),

          // Input.
          "[Proxy Settings]\r\nProxyType=1\r\nhttpProxy=www.google.com\r\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Handle blank lines and mixed line endings"),

          // Input.
          "[Proxy Settings]\r\n\nProxyType=1\n\r\nhttpProxy=www.google.com\n\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Handle localized settings"),

          // Input.
          "[Proxy Settings]\nProxyType[$e]=1\nhttpProxy[$e]=www.google.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Ignore malformed localized settings"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "httpsProxy$e]=www.foo.com\nftpProxy=ftp.foo.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "ftp.foo.com:80",     // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Handle strange whitespace"),

          // Input.
          "[Proxy Settings]\nProxyType [$e] =2\n"
          "  Proxy Config Script =  http:// foo\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                // auto_detect
          GURL("http:// foo"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Ignore all of a line which is too long"),

          // Input.
          std::string("[Proxy Settings]\nProxyType=1\nftpProxy=ftp.foo.com\n") +
              long_line + "httpsProxy=www.foo.com\nhttpProxy=www.google.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "ftp.foo.com:80",     // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Indirect Proxy - no env vars set"),

          // Input.
          "[Proxy Settings]\nProxyType=4\nhttpProxy=http_proxy\n"
          "httpsProxy=https_proxy\nftpProxy=ftp_proxy\nNoProxyFor=no_proxy\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Indirect Proxy - with env vars set"),

          // Input.
          "[Proxy Settings]\nProxyType=4\nhttpProxy=http_proxy\n"
          "httpsProxy=https_proxy\nftpProxy=ftp_proxy\nNoProxyFor=no_proxy\n",
          {
              // env_values
              nullptr,                  // DESKTOP_SESSION
              nullptr,                  // HOME
              nullptr,                  // KDEHOME
              nullptr,                  // KDE_SESSION_VERSION
              nullptr,                  // XDG_CURRENT_DESKTOP
              nullptr,                  // auto_proxy
              nullptr,                  // all_proxy
              "www.normal.com",         // http_proxy
              "www.secure.com",         // https_proxy
              "ftp.foo.com",            // ftp_proxy
              nullptr, nullptr,         // SOCKS
              ".google.com, .kde.org",  // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerScheme(
              "www.normal.com:80",        // http
              "www.secure.com:80",        // https
              "ftp.foo.com:80",           // ftp
              "*.google.com,*.kde.org"),  // bypass rules
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "] %s", i,
                                    tests[i].description.c_str()));
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values = tests[i].env_values;
    // Force the KDE getter to be used and tell it where the test is.
    env->values.DESKTOP_SESSION = "kde4";
    env->values.KDEHOME = kde_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    // Overwrite the kioslaverc file.
    base::WriteFile(kioslaverc_, tests[i].kioslaverc.c_str(),
                    tests[i].kioslaverc.length());
    sync_config_getter.SetupAndInitialFetch();
    ProxyConfigService::ConfigAvailability availability =
        sync_config_getter.SyncGetLatestProxyConfig(&config);
    EXPECT_EQ(tests[i].availability, availability);

    if (availability == ProxyConfigService::CONFIG_VALID) {
      EXPECT_EQ(tests[i].auto_detect, config.auto_detect());
      EXPECT_EQ(tests[i].pac_url, config.pac_url());
      EXPECT_TRUE(tests[i].proxy_rules.Matches(config.proxy_rules()));
    }
  }
}

TEST_F(ProxyConfigServiceLinuxTest, KDEHomePicker) {
  // Auto detect proxy settings.
  std::string slaverc3 = "[Proxy Settings]\nProxyType=3\n";
  // Valid PAC URL.
  std::string slaverc4 = "[Proxy Settings]\nProxyType=2\n"
                             "Proxy Config Script=http://wpad/wpad.dat\n";
  GURL slaverc4_pac_url("http://wpad/wpad.dat");
  // Basic HTTP proxy setting.
  std::string slaverc5 =
      "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com 80\n";
  ProxyRulesExpectation slaverc5_rules =
      ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                       "",                   // https
                                       "",                   // ftp
                                       "");                  // bypass rules

  // Overwrite the .kde kioslaverc file.
  base::WriteFile(kioslaverc_, slaverc3.c_str(), slaverc3.length());

  // If .kde4 exists it will mess up the first test. It should not, as
  // we created the directory for $HOME in the test setup.
  CHECK(!base::DirectoryExists(kde4_home_));

  { SCOPED_TRACE("KDE4, no .kde4 directory, verify fallback");
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values.DESKTOP_SESSION = "kde4";
    env->values.HOME = user_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_TRUE(config.auto_detect());
    EXPECT_EQ(GURL(), config.pac_url());
  }

  // Now create .kde4 and put a kioslaverc in the config directory.
  // Note that its timestamp will be at least as new as the .kde one.
  base::CreateDirectory(kde4_config_);
  base::WriteFile(kioslaverc4_, slaverc4.c_str(), slaverc4.length());
  CHECK(base::PathExists(kioslaverc4_));

  { SCOPED_TRACE("KDE4, .kde4 directory present, use it");
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values.DESKTOP_SESSION = "kde4";
    env->values.HOME = user_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_FALSE(config.auto_detect());
    EXPECT_EQ(slaverc4_pac_url, config.pac_url());
  }

  { SCOPED_TRACE("KDE3, .kde4 directory present, ignore it");
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values.DESKTOP_SESSION = "kde";
    env->values.HOME = user_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_TRUE(config.auto_detect());
    EXPECT_EQ(GURL(), config.pac_url());
  }

  { SCOPED_TRACE("KDE4, .kde4 directory present, KDEHOME set to .kde");
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values.DESKTOP_SESSION = "kde4";
    env->values.HOME = user_home_.value().c_str();
    env->values.KDEHOME = kde_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_TRUE(config.auto_detect());
    EXPECT_EQ(GURL(), config.pac_url());
  }

  // Finally, make the .kde4 config directory older than the .kde directory
  // and make sure we then use .kde instead of .kde4 since it's newer.
  base::TouchFile(kde4_config_, base::Time(), base::Time());

  { SCOPED_TRACE("KDE4, very old .kde4 directory present, use .kde");
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values.DESKTOP_SESSION = "kde4";
    env->values.HOME = user_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_TRUE(config.auto_detect());
    EXPECT_EQ(GURL(), config.pac_url());
  }

  // For KDE 5 create ${HOME}/.config and put a kioslaverc in the directory.
  base::CreateDirectory(config_home_);
  base::WriteFile(kioslaverc5_, slaverc5.c_str(), slaverc5.length());
  CHECK(base::PathExists(kioslaverc5_));

  {
    SCOPED_TRACE("KDE5, .kde and .kde4 present, use .config");
    std::unique_ptr<MockEnvironment> env(new MockEnvironment);
    env->values.XDG_CURRENT_DESKTOP = "KDE";
    env->values.KDE_SESSION_VERSION = "5";
    env->values.HOME = user_home_.value().c_str();
    SynchConfigGetter sync_config_getter(
        new ProxyConfigServiceLinux(std::move(env)));
    ProxyConfig config;
    sync_config_getter.SetupAndInitialFetch();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_FALSE(config.auto_detect());
    EXPECT_TRUE(slaverc5_rules.Matches(config.proxy_rules()));
  }
}

}  // namespace

}  // namespace net

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TransportSecurityState maintains an in memory database containing the
// list of hosts that currently have transport security enabled. This
// singleton object deals with writing that data out to disk as needed and
// loading it at startup.

// At startup we need to load the transport security state from the
// disk. For the moment, we don't want to delay startup for this load, so we
// let the TransportSecurityState run for a while without being loaded.
// This means that it's possible for pages opened very quickly not to get the
// correct transport security information.
//
// To load the state, we schedule a Task on background_runner, which
// deserializes and configures the TransportSecurityState.
//
// The TransportSecurityState object supports running a callback function
// when it changes. This object registers the callback, pointing at itself.
//
// TransportSecurityState calls...
// TransportSecurityPersister::StateIsDirty
//   since the callback isn't allowed to block or reenter, we schedule a Task
//   on the file task runner after some small amount of time
//
// ...
//
// TransportSecurityPersister::SerializeState
//   copies the current state of the TransportSecurityState, serializes
//   and writes to disk.

#ifndef NET_HTTP_TRANSPORT_SECURITY_PERSISTER_H_
#define NET_HTTP_TRANSPORT_SECURITY_PERSISTER_H_

#include <string>

#include "base/files/file_path.h"
#include "base/files/important_file_writer.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "net/base/net_export.h"
#include "net/http/transport_security_state.h"

namespace base {
class DictionaryValue;
class SequencedTaskRunner;
}

namespace net {

// Reads and updates on-disk TransportSecurity state. Clients of this class
// should create, destroy, and call into it from one thread.
//
// background_runner is the task runner this class should use internally to
// perform file IO, and can optionally be associated with a different thread.
class NET_EXPORT TransportSecurityPersister
    : public TransportSecurityState::Delegate,
      public base::ImportantFileWriter::DataSerializer {
 public:
  TransportSecurityPersister(
      TransportSecurityState* state,
      const base::FilePath& profile_path,
      const scoped_refptr<base::SequencedTaskRunner>& background_runner,
      bool readonly);
  ~TransportSecurityPersister() override;

  // Called by the TransportSecurityState when it changes its state.
  void StateIsDirty(TransportSecurityState*) override;

  // ImportantFileWriter::DataSerializer:
  //
  // Serializes |transport_security_state_| into |*output|. Returns true if
  // all STS and PKP states were serialized correctly.
  //
  // The serialization format is JSON; the JSON represents a dictionary of
  // host:DomainState pairs (host is a string). The DomainState contains
  // the STS and PKP states and is represented as a dictionary containing
  // the following keys and value types (not all keys will always be
  // present):
  //
  //     "sts_include_subdomains": true|false
  //     "pkp_include_subdomains": true|false
  //     "created": double
  //     "expiry": double
  //     "dynamic_spki_hashes_expiry": double
  //     "mode": "default"|"force-https"
  //             legacy value synonyms "strict" = "force-https"
  //                                   "pinning-only" = "default"
  //             legacy value "spdy-only" is unused and ignored
  //     "static_spki_hashes": list of strings
  //         legacy key synonym "preloaded_spki_hashes"
  //     "bad_static_spki_hashes": list of strings
  //         legacy key synonym "bad_preloaded_spki_hashes"
  //     "dynamic_spki_hashes": list of strings
  //
  // The JSON dictionary keys are strings containing
  // Base64(SHA256(TransportSecurityState::CanonicalizeHost(domain))).
  // The reason for hashing them is so that the stored state does not
  // trivially reveal a user's browsing history to an attacker reading the
  // serialized state on disk.
  bool SerializeData(std::string* data) override;

  // Clears any existing non-static entries, and then re-populates
  // |transport_security_state_|.
  //
  // Sets |*dirty| to true if the new state differs from the persisted
  // state; false otherwise.
  bool LoadEntries(const std::string& serialized, bool* dirty);

 private:
  // Populates |state| from the JSON string |serialized|. Returns true if
  // all entries were parsed and deserialized correctly.
  //
  // Sets |*dirty| to true if the new state differs from the persisted
  // state; false otherwise.
  static bool Deserialize(const std::string& serialized,
                          bool* dirty,
                          TransportSecurityState* state);

  // Populates |host| with default values for the STS and PKP states.
  // These default values represent "null" states and are only useful to keep
  // the entries in the resulting JSON consistent. The deserializer will ignore
  // "null" states.
  // TODO(davidben): This can be removed when the STS and PKP states are stored
  // independently on disk. https://crbug.com/470295
  void PopulateEntryWithDefaults(base::DictionaryValue* host);

  void CompleteLoad(const std::string& state);

  TransportSecurityState* transport_security_state_;

  // Helper for safely writing the data.
  base::ImportantFileWriter writer_;

  scoped_refptr<base::SequencedTaskRunner> foreground_runner_;
  scoped_refptr<base::SequencedTaskRunner> background_runner_;

  // Whether or not we're in read-only mode.
  const bool readonly_;

  base::WeakPtrFactory<TransportSecurityPersister> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(TransportSecurityPersister);
};

}  // namespace net

#endif  // NET_HTTP_TRANSPORT_SECURITY_PERSISTER_H_

// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MEMORY_MEMORY_CLIENT_REGISTRY_H_
#define BASE_MEMORY_MEMORY_CLIENT_REGISTRY_H_

#include "base/base_export.h"
#include "base/memory/memory_coordinator_client.h"
#include "base/memory/singleton.h"
#include "base/observer_list_threadsafe.h"

namespace base {

// MemoryCoordinatorClientRegistry is the registry for
// MemoryCoordinatorClients. Callbacks of MemoryCoordinatorClient are called
// via MemoryCoordinator.
class BASE_EXPORT MemoryCoordinatorClientRegistry {
 public:
  static MemoryCoordinatorClientRegistry* GetInstance();

  ~MemoryCoordinatorClientRegistry();

  // Registers/unregisters a client. Does not take ownership of client.
  void Register(MemoryCoordinatorClient* client);
  void Unregister(MemoryCoordinatorClient* client);

  using ClientList = ObserverListThreadSafe<MemoryCoordinatorClient>;
  ClientList* clients() { return clients_.get(); }

 private:
  friend struct DefaultSingletonTraits<MemoryCoordinatorClientRegistry>;

  MemoryCoordinatorClientRegistry();

  scoped_refptr<ClientList> clients_;
};

}  // namespace base

#endif  // BASE_MEMORY_MEMORY_CLIENT_REGISTRY_H_

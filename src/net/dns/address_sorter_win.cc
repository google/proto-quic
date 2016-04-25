// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/address_sorter.h"

#include <winsock2.h>

#include <algorithm>

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/free_deleter.h"
#include "base/threading/worker_pool.h"
#include "base/win/windows_version.h"
#include "net/base/address_list.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/winsock_init.h"

namespace net {

namespace {

class AddressSorterWin : public AddressSorter {
 public:
  AddressSorterWin() {
    EnsureWinsockInit();
  }

  ~AddressSorterWin() override {}

  // AddressSorter:
  void Sort(const AddressList& list,
            const CallbackType& callback) const override {
    DCHECK(!list.empty());
    scoped_refptr<Job> job = new Job(list, callback);
  }

 private:
  // Executes the SIO_ADDRESS_LIST_SORT ioctl on the WorkerPool, and
  // performs the necessary conversions to/from AddressList.
  class Job : public base::RefCountedThreadSafe<Job> {
   public:
    Job(const AddressList& list, const CallbackType& callback)
        : callback_(callback),
          buffer_size_(sizeof(SOCKET_ADDRESS_LIST) +
                       list.size() * (sizeof(SOCKET_ADDRESS) +
                                      sizeof(SOCKADDR_STORAGE))),
          input_buffer_(reinterpret_cast<SOCKET_ADDRESS_LIST*>(
              malloc(buffer_size_))),
          output_buffer_(reinterpret_cast<SOCKET_ADDRESS_LIST*>(
              malloc(buffer_size_))),
          success_(false) {
      input_buffer_->iAddressCount = list.size();
      SOCKADDR_STORAGE* storage = reinterpret_cast<SOCKADDR_STORAGE*>(
          input_buffer_->Address + input_buffer_->iAddressCount);

      for (size_t i = 0; i < list.size(); ++i) {
        IPEndPoint ipe = list[i];
        // Addresses must be sockaddr_in6.
        if (ipe.address().IsIPv4()) {
          ipe = IPEndPoint(ConvertIPv4ToIPv4MappedIPv6(ipe.address()),
                           ipe.port());
        }

        struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(storage + i);
        socklen_t addr_len = sizeof(SOCKADDR_STORAGE);
        bool result = ipe.ToSockAddr(addr, &addr_len);
        DCHECK(result);
        input_buffer_->Address[i].lpSockaddr = addr;
        input_buffer_->Address[i].iSockaddrLength = addr_len;
      }

      if (!base::WorkerPool::PostTaskAndReply(
          FROM_HERE,
          base::Bind(&Job::Run, this),
          base::Bind(&Job::OnComplete, this),
          false /* task is slow */)) {
        LOG(ERROR) << "WorkerPool::PostTaskAndReply failed";
        OnComplete();
      }
    }

   private:
    friend class base::RefCountedThreadSafe<Job>;
    ~Job() {}

    // Executed on the WorkerPool.
    void Run() {
      SOCKET sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      if (sock == INVALID_SOCKET)
        return;
      DWORD result_size = 0;
      int result = WSAIoctl(sock, SIO_ADDRESS_LIST_SORT, input_buffer_.get(),
                            buffer_size_, output_buffer_.get(), buffer_size_,
                            &result_size, NULL, NULL);
      if (result == SOCKET_ERROR) {
        LOG(ERROR) << "SIO_ADDRESS_LIST_SORT failed " << WSAGetLastError();
      } else {
        success_ = true;
      }
      closesocket(sock);
    }

    // Executed on the calling thread.
    void OnComplete() {
      AddressList list;
      if (success_) {
        list.reserve(output_buffer_->iAddressCount);
        for (int i = 0; i < output_buffer_->iAddressCount; ++i) {
          IPEndPoint ipe;
          bool result =
              ipe.FromSockAddr(output_buffer_->Address[i].lpSockaddr,
                               output_buffer_->Address[i].iSockaddrLength);
          DCHECK(result) << "Unable to roundtrip between IPEndPoint and "
                         << "SOCKET_ADDRESS!";
          // Unmap V4MAPPED IPv6 addresses so that Happy Eyeballs works.
          if (ipe.address().IsIPv4MappedIPv6()) {
            ipe = IPEndPoint(ConvertIPv4MappedIPv6ToIPv4(ipe.address()),
                             ipe.port());
          }
          list.push_back(ipe);
        }
      }
      callback_.Run(success_, list);
    }

    const CallbackType callback_;
    const size_t buffer_size_;
    std::unique_ptr<SOCKET_ADDRESS_LIST, base::FreeDeleter> input_buffer_;
    std::unique_ptr<SOCKET_ADDRESS_LIST, base::FreeDeleter> output_buffer_;
    bool success_;

    DISALLOW_COPY_AND_ASSIGN(Job);
  };

  DISALLOW_COPY_AND_ASSIGN(AddressSorterWin);
};

// Merges |list_ipv4| and |list_ipv6| before passing it to |callback|, but
// only if |success| is true.
void MergeResults(const AddressSorter::CallbackType& callback,
                  const AddressList& list_ipv4,
                  bool success,
                  const AddressList& list_ipv6) {
  if (!success) {
    callback.Run(false, AddressList());
    return;
  }
  AddressList list;
  list.insert(list.end(), list_ipv6.begin(), list_ipv6.end());
  list.insert(list.end(), list_ipv4.begin(), list_ipv4.end());
  callback.Run(true, list);
}

// Wrapper for AddressSorterWin which does not sort IPv4 or IPv4-mapped
// addresses but always puts them at the end of the list. Needed because the
// SIO_ADDRESS_LIST_SORT does not support IPv4 addresses on Windows XP.
class AddressSorterWinXP : public AddressSorter {
 public:
  AddressSorterWinXP() {}
  ~AddressSorterWinXP() override {}

  // AddressSorter:
  void Sort(const AddressList& list,
            const CallbackType& callback) const override {
    AddressList list_ipv4;
    AddressList list_ipv6;
    for (size_t i = 0; i < list.size(); ++i) {
      const IPEndPoint& ipe = list[i];
      if (ipe.GetFamily() == ADDRESS_FAMILY_IPV4) {
        list_ipv4.push_back(ipe);
      } else {
        list_ipv6.push_back(ipe);
      }
    }
    if (!list_ipv6.empty()) {
      sorter_.Sort(list_ipv6, base::Bind(&MergeResults, callback, list_ipv4));
    } else {
      NOTREACHED() << "Should not be called with IPv4-only addresses.";
      callback.Run(true, list);
    }
  }

 private:
  AddressSorterWin sorter_;

  DISALLOW_COPY_AND_ASSIGN(AddressSorterWinXP);
};

}  // namespace

// static
std::unique_ptr<AddressSorter> AddressSorter::CreateAddressSorter() {
  if (base::win::GetVersion() < base::win::VERSION_VISTA)
    return std::unique_ptr<AddressSorter>(new AddressSorterWinXP());
  return std::unique_ptr<AddressSorter>(new AddressSorterWin());
}

}  // namespace net


// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_list.h"

#include "base/callback.h"
#include "base/logging.h"
#include "base/strings/string_tokenizer.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/log/net_log_event_type.h"
#include "net/proxy/proxy_server.h"

using base::TimeDelta;
using base::TimeTicks;

namespace net {

ProxyList::ProxyList() {
}

ProxyList::ProxyList(const ProxyList& other) = default;

ProxyList::~ProxyList() {
}

void ProxyList::Set(const std::string& proxy_uri_list) {
  proxies_.clear();
  base::StringTokenizer str_tok(proxy_uri_list, ";");
  while (str_tok.GetNext()) {
    ProxyServer uri = ProxyServer::FromURI(
        str_tok.token_begin(), str_tok.token_end(), ProxyServer::SCHEME_HTTP);
    // Silently discard malformed inputs.
    if (uri.is_valid())
      proxies_.push_back(uri);
  }
}

void ProxyList::SetSingleProxyServer(const ProxyServer& proxy_server) {
  proxies_.clear();
  AddProxyServer(proxy_server);
}

void ProxyList::AddProxyServer(const ProxyServer& proxy_server) {
  if (proxy_server.is_valid())
    proxies_.push_back(proxy_server);
}

void ProxyList::DeprioritizeBadProxies(
    const ProxyRetryInfoMap& proxy_retry_info) {
  // Partition the proxy list in two:
  //   (1) the known bad proxies
  //   (2) everything else
  std::vector<ProxyServer> good_proxies;
  std::vector<ProxyServer> bad_proxies_to_try;

  std::vector<ProxyServer>::const_iterator iter = proxies_.begin();
  for (; iter != proxies_.end(); ++iter) {
    ProxyRetryInfoMap::const_iterator bad_proxy =
        proxy_retry_info.find(iter->ToURI());
    if (bad_proxy != proxy_retry_info.end()) {
      // This proxy is bad. Check if it's time to retry.
      if (bad_proxy->second.bad_until >= TimeTicks::Now()) {
        // still invalid.
        if (bad_proxy->second.try_while_bad)
          bad_proxies_to_try.push_back(*iter);
        continue;
      }
    }
    good_proxies.push_back(*iter);
  }

  // "proxies_ = good_proxies + bad_proxies"
  proxies_.swap(good_proxies);
  proxies_.insert(proxies_.end(), bad_proxies_to_try.begin(),
                  bad_proxies_to_try.end());
}

void ProxyList::RemoveProxiesWithoutScheme(int scheme_bit_field) {
  for (std::vector<ProxyServer>::iterator it = proxies_.begin();
       it != proxies_.end(); ) {
    if (!(scheme_bit_field & it->scheme())) {
      it = proxies_.erase(it);
      continue;
    }
    ++it;
  }
}

void ProxyList::Clear() {
  proxies_.clear();
}

bool ProxyList::IsEmpty() const {
  return proxies_.empty();
}

size_t ProxyList::size() const {
  return proxies_.size();
}

// Returns true if |*this| lists the same proxies as |other|.
bool ProxyList::Equals(const ProxyList& other) const {
  if (size() != other.size())
    return false;
  return proxies_ == other.proxies_;
}

const ProxyServer& ProxyList::Get() const {
  DCHECK(!proxies_.empty());
  return proxies_[0];
}

const std::vector<ProxyServer>& ProxyList::GetAll() const {
  return proxies_;
}

void ProxyList::SetFromPacString(const std::string& pac_string) {
  base::StringTokenizer entry_tok(pac_string, ";");
  proxies_.clear();
  while (entry_tok.GetNext()) {
    ProxyServer uri = ProxyServer::FromPacString(
        entry_tok.token_begin(), entry_tok.token_end());
    // Silently discard malformed inputs.
    if (uri.is_valid())
      proxies_.push_back(uri);
  }

  // If we failed to parse anything from the PAC results list, fallback to
  // DIRECT (this basically means an error in the PAC script).
  if (proxies_.empty()) {
    proxies_.push_back(ProxyServer::Direct());
  }
}

std::string ProxyList::ToPacString() const {
  std::string proxy_list;
  std::vector<ProxyServer>::const_iterator iter = proxies_.begin();
  for (; iter != proxies_.end(); ++iter) {
    if (!proxy_list.empty())
      proxy_list += ";";
    proxy_list += iter->ToPacString();
  }
  return proxy_list.empty() ? std::string() : proxy_list;
}

std::unique_ptr<base::ListValue> ProxyList::ToValue() const {
  std::unique_ptr<base::ListValue> list(new base::ListValue());
  for (size_t i = 0; i < proxies_.size(); ++i)
    list->AppendString(proxies_[i].ToURI());
  return list;
}

bool ProxyList::Fallback(ProxyRetryInfoMap* proxy_retry_info,
                         int net_error,
                         const NetLogWithSource& net_log) {
  // TODO(eroman): It would be good if instead of removing failed proxies
  // from the list, we simply annotated them with the error code they failed
  // with. Of course, ProxyService::ReconsiderProxyAfterError() would need to
  // be given this information by the network transaction.
  //
  // The advantage of this approach is when the network transaction
  // fails, we could output the full list of proxies that were attempted, and
  // why each one of those failed (as opposed to just the last failure).
  //
  // And also, before failing the transaction wholesale, we could go back and
  // retry the "bad proxies" which we never tried to begin with.
  // (RemoveBadProxies would annotate them as 'expected bad' rather then delete
  // them from the list, so we would know what they were).

  if (proxies_.empty()) {
    NOTREACHED();
    return false;
  }
  // By default, proxies are not retried for 5 minutes.
  UpdateRetryInfoOnFallback(proxy_retry_info, TimeDelta::FromMinutes(5), true,
                            std::vector<ProxyServer>(), net_error, net_log);

  // Remove this proxy from our list.
  proxies_.erase(proxies_.begin());
  return !proxies_.empty();
}

void ProxyList::AddProxyToRetryList(ProxyRetryInfoMap* proxy_retry_info,
                                    base::TimeDelta retry_delay,
                                    bool try_while_bad,
                                    const ProxyServer& proxy_to_retry,
                                    int net_error,
                                    const NetLogWithSource& net_log) const {
  // Mark this proxy as bad.
  TimeTicks bad_until = TimeTicks::Now() + retry_delay;
  std::string proxy_key = proxy_to_retry.ToURI();
  ProxyRetryInfoMap::iterator iter = proxy_retry_info->find(proxy_key);
  if (iter == proxy_retry_info->end() || bad_until > iter->second.bad_until) {
    ProxyRetryInfo retry_info;
    retry_info.current_delay = retry_delay;
    retry_info.bad_until = bad_until;
    retry_info.try_while_bad = try_while_bad;
    retry_info.net_error = net_error;
    (*proxy_retry_info)[proxy_key] = retry_info;
  }
  net_log.AddEvent(NetLogEventType::PROXY_LIST_FALLBACK,
                   NetLog::StringCallback("bad_proxy", &proxy_key));
}

void ProxyList::UpdateRetryInfoOnFallback(
    ProxyRetryInfoMap* proxy_retry_info,
    base::TimeDelta retry_delay,
    bool reconsider,
    const std::vector<ProxyServer>& additional_proxies_to_bypass,
    int net_error,
    const NetLogWithSource& net_log) const {
  DCHECK(!retry_delay.is_zero());

  if (proxies_.empty()) {
    NOTREACHED();
    return;
  }

  if (!proxies_[0].is_direct()) {
    AddProxyToRetryList(proxy_retry_info,
                        retry_delay,
                        reconsider,
                        proxies_[0],
                        net_error,
                        net_log);
    // If any additional proxies to bypass are specified, add to the retry map
    // as well.
    for (const ProxyServer& additional_proxy : additional_proxies_to_bypass) {
      AddProxyToRetryList(proxy_retry_info, retry_delay, reconsider,
                          additional_proxy, net_error, net_log);
    }
  }
}

}  // namespace net

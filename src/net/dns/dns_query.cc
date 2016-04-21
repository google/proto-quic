// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_query.h"

#include "base/big_endian.h"
#include "base/memory/ptr_util.h"
#include "base/sys_byteorder.h"
#include "net/base/io_buffer.h"
#include "net/dns/dns_protocol.h"
#include "net/dns/dns_util.h"

namespace net {

// DNS query consists of a 12-byte header followed by a question section.
// For details, see RFC 1035 section 4.1.1.  This header template sets RD
// bit, which directs the name server to pursue query recursively, and sets
// the QDCOUNT to 1, meaning the question section has a single entry.
DnsQuery::DnsQuery(uint16_t id, const base::StringPiece& qname, uint16_t qtype)
    : qname_size_(qname.size()),
      io_buffer_(
          new IOBufferWithSize(sizeof(dns_protocol::Header) + question_size())),
      header_(reinterpret_cast<dns_protocol::Header*>(io_buffer_->data())) {
  DCHECK(!DNSDomainToString(qname).empty());
  *header_ = {};
  header_->id = base::HostToNet16(id);
  header_->flags = base::HostToNet16(dns_protocol::kFlagRD);
  header_->qdcount = base::HostToNet16(1);

  // Write question section after the header.
  base::BigEndianWriter writer(
      io_buffer_->data() + sizeof(dns_protocol::Header), question_size());
  writer.WriteBytes(qname.data(), qname.size());
  writer.WriteU16(qtype);
  writer.WriteU16(dns_protocol::kClassIN);
}

DnsQuery::~DnsQuery() {
}

std::unique_ptr<DnsQuery> DnsQuery::CloneWithNewId(uint16_t id) const {
  return base::WrapUnique(new DnsQuery(*this, id));
}

uint16_t DnsQuery::id() const {
  return base::NetToHost16(header_->id);
}

base::StringPiece DnsQuery::qname() const {
  return base::StringPiece(io_buffer_->data() + sizeof(dns_protocol::Header),
                           qname_size_);
}

uint16_t DnsQuery::qtype() const {
  uint16_t type;
  base::ReadBigEndian<uint16_t>(
      io_buffer_->data() + sizeof(dns_protocol::Header) + qname_size_, &type);
  return type;
}

base::StringPiece DnsQuery::question() const {
  return base::StringPiece(io_buffer_->data() + sizeof(dns_protocol::Header),
                           question_size());
}

void DnsQuery::set_flags(uint16_t flags) {
  header_->flags = flags;
}

DnsQuery::DnsQuery(const DnsQuery& orig, uint16_t id) {
  qname_size_ = orig.qname_size_;
  io_buffer_ = new IOBufferWithSize(orig.io_buffer()->size());
  memcpy(io_buffer_.get()->data(), orig.io_buffer()->data(),
         io_buffer_.get()->size());
  header_ = reinterpret_cast<dns_protocol::Header*>(io_buffer_->data());
  header_->id = base::HostToNet16(id);
}

}  // namespace net

// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/ip_address.h"

#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "net/base/ip_address_number.h"
#include "net/base/parse_number.h"
#include "url/gurl.h"
#include "url/url_canon_ip.h"

namespace {

bool IPAddressPrefixCheck(const std::vector<uint8_t>& ip_address,
                          const unsigned char* ip_prefix,
                          size_t prefix_length_in_bits) {
  // Compare all the bytes that fall entirely within the prefix.
  int num_entire_bytes_in_prefix = prefix_length_in_bits / 8;
  for (int i = 0; i < num_entire_bytes_in_prefix; ++i) {
    if (ip_address[i] != ip_prefix[i])
      return false;
  }

  // In case the prefix was not a multiple of 8, there will be 1 byte
  // which is only partially masked.
  int remaining_bits = prefix_length_in_bits % 8;
  if (remaining_bits != 0) {
    unsigned char mask = 0xFF << (8 - remaining_bits);
    int i = num_entire_bytes_in_prefix;
    if ((ip_address[i] & mask) != (ip_prefix[i] & mask))
      return false;
  }
  return true;
}

}  // namespace

namespace net {

IPAddress::IPAddress() {}

IPAddress::IPAddress(const IPAddressNumber& address) : ip_address_(address) {}

IPAddress::IPAddress(const IPAddress& other) = default;

IPAddress::IPAddress(const uint8_t* address, size_t address_len)
    : ip_address_(address, address + address_len) {}

IPAddress::IPAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
  ip_address_.reserve(4);
  ip_address_.push_back(b0);
  ip_address_.push_back(b1);
  ip_address_.push_back(b2);
  ip_address_.push_back(b3);
}

IPAddress::IPAddress(uint8_t b0,
                     uint8_t b1,
                     uint8_t b2,
                     uint8_t b3,
                     uint8_t b4,
                     uint8_t b5,
                     uint8_t b6,
                     uint8_t b7,
                     uint8_t b8,
                     uint8_t b9,
                     uint8_t b10,
                     uint8_t b11,
                     uint8_t b12,
                     uint8_t b13,
                     uint8_t b14,
                     uint8_t b15) {
  const uint8_t address[] = {b0, b1, b2,  b3,  b4,  b5,  b6,  b7,
                             b8, b9, b10, b11, b12, b13, b14, b15};
  ip_address_ = std::vector<uint8_t>(std::begin(address), std::end(address));
}

IPAddress::~IPAddress() {}

bool IPAddress::IsIPv4() const {
  return ip_address_.size() == kIPv4AddressSize;
}

bool IPAddress::IsIPv6() const {
  return ip_address_.size() == kIPv6AddressSize;
}

bool IPAddress::IsValid() const {
  return IsIPv4() || IsIPv6();
}

// Don't compare IPv4 and IPv6 addresses (they have different range
// reservations). Keep separate reservation arrays for each IP type, and
// consolidate adjacent reserved ranges within a reservation array when
// possible.
// Sources for info:
// www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
// www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
// They're formatted here with the prefix as the last element. For example:
// 10.0.0.0/8 becomes 10,0,0,0,8 and fec0::/10 becomes 0xfe,0xc0,0,0,0...,10.
bool IPAddress::IsReserved() const {
  static const unsigned char kReservedIPv4[][5] = {
      {0, 0, 0, 0, 8},     {10, 0, 0, 0, 8},      {100, 64, 0, 0, 10},
      {127, 0, 0, 0, 8},   {169, 254, 0, 0, 16},  {172, 16, 0, 0, 12},
      {192, 0, 2, 0, 24},  {192, 88, 99, 0, 24},  {192, 168, 0, 0, 16},
      {198, 18, 0, 0, 15}, {198, 51, 100, 0, 24}, {203, 0, 113, 0, 24},
      {224, 0, 0, 0, 3}};
  static const unsigned char kReservedIPv6[][17] = {
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8},
      {0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
      {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
      {0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3},
      {0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
      {0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
      {0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6},
      {0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7},
      {0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
      {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10},
      {0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10},
  };
  size_t array_size = 0;
  const unsigned char* array = nullptr;
  switch (ip_address_.size()) {
    case kIPv4AddressSize:
      array_size = arraysize(kReservedIPv4);
      array = kReservedIPv4[0];
      break;
    case kIPv6AddressSize:
      array_size = arraysize(kReservedIPv6);
      array = kReservedIPv6[0];
      break;
  }
  if (!array)
    return false;
  size_t width = ip_address_.size() + 1;
  for (size_t i = 0; i < array_size; ++i, array += width) {
    if (IPAddressPrefixCheck(ip_address_, array, array[width - 1]))
      return true;
  }
  return false;
}

bool IPAddress::IsZero() const {
  for (auto x : ip_address_) {
    if (x != 0)
      return false;
  }

  return !empty();
}

bool IPAddress::IsIPv4MappedIPv6() const {
  return net::IsIPv4Mapped(ip_address_);
}

std::string IPAddress::ToString() const {
  return IPAddressToString(ip_address_);
}

bool IPAddress::AssignFromIPLiteral(const base::StringPiece& ip_literal) {
  std::vector<uint8_t> number;
  if (!ParseIPLiteralToNumber(ip_literal, &number))
    return false;

  std::swap(number, ip_address_);
  return true;
}

// static
IPAddress IPAddress::IPv4Localhost() {
  static const uint8_t kLocalhostIPv4[] = {127, 0, 0, 1};
  return IPAddress(kLocalhostIPv4);
}

// static
IPAddress IPAddress::IPv6Localhost() {
  static const uint8_t kLocalhostIPv6[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 1};
  return IPAddress(kLocalhostIPv6);
}

// static
IPAddress IPAddress::AllZeros(size_t num_zero_bytes) {
  return IPAddress(std::vector<uint8_t>(num_zero_bytes));
}

// static
IPAddress IPAddress::IPv4AllZeros() {
  return AllZeros(kIPv4AddressSize);
}

// static
IPAddress IPAddress::IPv6AllZeros() {
  return AllZeros(kIPv6AddressSize);
}

bool IPAddress::operator==(const IPAddress& that) const {
  return ip_address_ == that.ip_address_;
}

bool IPAddress::operator!=(const IPAddress& that) const {
  return ip_address_ != that.ip_address_;
}

bool IPAddress::operator<(const IPAddress& that) const {
  // Sort IPv4 before IPv6.
  if (ip_address_.size() != that.ip_address_.size()) {
    return ip_address_.size() < that.ip_address_.size();
  }

  return ip_address_ < that.ip_address_;
}

std::string IPAddressToStringWithPort(const IPAddress& address, uint16_t port) {
  return IPAddressToStringWithPort(address.bytes(), port);
}

std::string IPAddressToPackedString(const IPAddress& address) {
  return IPAddressToPackedString(address.bytes());
}

IPAddress ConvertIPv4ToIPv4MappedIPv6(const IPAddress& address) {
  return IPAddress(ConvertIPv4NumberToIPv6Number(address.bytes()));
}

IPAddress ConvertIPv4MappedIPv6ToIPv4(const IPAddress& address) {
  return IPAddress(ConvertIPv4MappedToIPv4(address.bytes()));
}

bool IPAddressMatchesPrefix(const IPAddress& ip_address,
                            const IPAddress& ip_prefix,
                            size_t prefix_length_in_bits) {
  // Both the input IP address and the prefix IP address should be either IPv4
  // or IPv6.
  DCHECK(ip_address.IsValid());
  DCHECK(ip_prefix.IsValid());

  DCHECK_LE(prefix_length_in_bits, ip_prefix.size() * 8);

  // In case we have an IPv6 / IPv4 mismatch, convert the IPv4 addresses to
  // IPv6 addresses in order to do the comparison.
  if (ip_address.size() != ip_prefix.size()) {
    if (ip_address.IsIPv4()) {
      return IPAddressMatchesPrefix(ConvertIPv4ToIPv4MappedIPv6(ip_address),
                                    ip_prefix, prefix_length_in_bits);
    }
    return IPAddressMatchesPrefix(ip_address,
                                  ConvertIPv4ToIPv4MappedIPv6(ip_prefix),
                                  96 + prefix_length_in_bits);
  }

  return IPAddressPrefixCheck(ip_address.bytes(), ip_prefix.bytes().data(),
                              prefix_length_in_bits);
}

bool ParseCIDRBlock(const std::string& cidr_literal,
                    IPAddress* ip_address,
                    size_t* prefix_length_in_bits) {
  // We expect CIDR notation to match one of these two templates:
  //   <IPv4-literal> "/" <number of bits>
  //   <IPv6-literal> "/" <number of bits>

  std::vector<base::StringPiece> parts = base::SplitStringPiece(
      cidr_literal, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2)
    return false;

  // Parse the IP address.
  if (!ip_address->AssignFromIPLiteral(parts[0]))
    return false;

  // Parse the prefix length.
  uint32_t number_of_bits;
  if (!ParseUint32(parts[1], &number_of_bits))
    return false;

  // Make sure the prefix length is in a valid range.
  if (number_of_bits > ip_address->size() * 8)
    return false;

  *prefix_length_in_bits = number_of_bits;
  return true;
}

bool ParseURLHostnameToAddress(const std::string& hostname,
                               IPAddress* ip_address) {
  if (hostname.size() >= 2 && hostname.front() == '[' &&
      hostname.back() == ']') {
    // Strip the square brackets that surround IPv6 literals.
    auto ip_literal =
        base::StringPiece(hostname).substr(1, hostname.size() - 2);
    return ip_address->AssignFromIPLiteral(ip_literal) && ip_address->IsIPv6();
  }

  return ip_address->AssignFromIPLiteral(hostname) && ip_address->IsIPv4();
}

unsigned CommonPrefixLength(const IPAddress& a1, const IPAddress& a2) {
  return CommonPrefixLength(a1.bytes(), a2.bytes());
}

unsigned MaskPrefixLength(const IPAddress& mask) {
  return MaskPrefixLength(mask.bytes());
}

}  // namespace net

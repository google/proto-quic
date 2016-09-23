// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include "base/command_line.h"
#include "net/base/io_buffer.h"
#include "net/filter/filter.h"
#include "net/filter/mock_filter_context.h"

using net::Filter;

namespace {

// Print the command line help.
void PrintHelp(const char* command_line_name) {
  std::cout << command_line_name << " content_encoding [content_encoding]..."
            << std::endl
            << std::endl;
  std::cout << "Decodes the stdin into the stdout using an content_encoding "
            << "list given in arguments. This list is expected to be the "
            << "Content-Encoding HTTP response header's value split by ','."
            << std::endl;
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  std::vector<std::string> content_encodings = command_line.GetArgs();
  if (content_encodings.size() == 0) {
    PrintHelp(argv[0]);
    return 1;
  }

  std::vector<Filter::FilterType> filter_types;
  for (const auto& content_encoding : content_encodings) {
    Filter::FilterType filter_type =
        Filter::ConvertEncodingToType(content_encoding);
    if (filter_type == Filter::FILTER_TYPE_UNSUPPORTED) {
      std::cerr << "Unsupported decoder '" << content_encoding << "'."
                << std::endl;
      return 1;
    }
    filter_types.push_back(filter_type);
  }

  net::MockFilterContext filter_context;
  std::unique_ptr<Filter> filter(Filter::Factory(filter_types, filter_context));
  if (!filter) {
    std::cerr << "Couldn't create the decoder." << std::endl;
    return 1;
  }

  net::IOBuffer* pre_filter_buf = filter->stream_buffer();
  int pre_filter_buf_len = filter->stream_buffer_size();
  while (std::cin) {
    std::cin.read(pre_filter_buf->data(), pre_filter_buf_len);
    int pre_filter_data_len = std::cin.gcount();
    filter->FlushStreamBuffer(pre_filter_data_len);

    while (true) {
      const int kPostFilterBufLen = 4096;
      char post_filter_buf[kPostFilterBufLen];
      int post_filter_data_len = kPostFilterBufLen;
      Filter::FilterStatus filter_status =
          filter->ReadData(post_filter_buf, &post_filter_data_len);
      std::cout.write(post_filter_buf, post_filter_data_len);
      if (filter_status == Filter::FILTER_ERROR) {
        std::cerr << "Couldn't decode stdin." << std::endl;
        return 1;
      } else if (filter_status != Filter::FILTER_OK) {
        break;
      }
    }
  }

  return 0;
}

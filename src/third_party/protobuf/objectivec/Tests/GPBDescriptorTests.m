// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// https://developers.google.com/protocol-buffers/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#import "GPBTestUtilities.h"

#import <objc/runtime.h>

#import "GPBDescriptor.h"
#import "google/protobuf/Unittest.pbobjc.h"
#import "google/protobuf/UnittestObjc.pbobjc.h"
#import "google/protobuf/Descriptor.pbobjc.h"

@interface DescriptorTests : GPBTestCase
@end

@implementation DescriptorTests

- (void)testDescriptor_containingType {
  GPBDescriptor *testAllTypesDesc = [TestAllTypes descriptor];
  GPBDescriptor *nestedMessageDesc = [TestAllTypes_NestedMessage descriptor];
  XCTAssertNil(testAllTypesDesc.containingType);
  XCTAssertNotNil(nestedMessageDesc.containingType);
  XCTAssertEqual(nestedMessageDesc.containingType, testAllTypesDesc);  // Ptr comparison
}

- (void)testDescriptor_fullName {
  GPBDescriptor *testAllTypesDesc = [TestAllTypes descriptor];
  XCTAssertEqualObjects(testAllTypesDesc.fullName, @"protobuf_unittest.TestAllTypes");
  GPBDescriptor *nestedMessageDesc = [TestAllTypes_NestedMessage descriptor];
  XCTAssertEqualObjects(nestedMessageDesc.fullName, @"protobuf_unittest.TestAllTypes.NestedMessage");

  // Prefixes removed.
  GPBDescriptor *descDesc = [GPBDescriptorProto descriptor];
  XCTAssertEqualObjects(descDesc.fullName, @"google.protobuf.DescriptorProto");
  GPBDescriptor *descExtRngDesc = [GPBDescriptorProto_ExtensionRange descriptor];
  XCTAssertEqualObjects(descExtRngDesc.fullName, @"google.protobuf.DescriptorProto.ExtensionRange");

  // Things that get "_Class" added.
  GPBDescriptor *pointDesc = [Point_Class descriptor];
  XCTAssertEqualObjects(pointDesc.fullName, @"protobuf_unittest.Point");
  GPBDescriptor *pointRectDesc = [Point_Rect descriptor];
  XCTAssertEqualObjects(pointRectDesc.fullName, @"protobuf_unittest.Point.Rect");
}

- (void)testFieldDescriptor {
  GPBDescriptor *descriptor = [TestAllTypes descriptor];

  // Nested Enum
  GPBFieldDescriptor *fieldDescriptorWithName =
      [descriptor fieldWithName:@"optionalNestedEnum"];
  XCTAssertNotNil(fieldDescriptorWithName);
  GPBFieldDescriptor *fieldDescriptorWithNumber =
      [descriptor fieldWithNumber:21];
  XCTAssertNotNil(fieldDescriptorWithNumber);
  XCTAssertEqual(fieldDescriptorWithName, fieldDescriptorWithNumber);
  XCTAssertNotNil(fieldDescriptorWithNumber.enumDescriptor);
  XCTAssertEqualObjects(fieldDescriptorWithNumber.enumDescriptor.name,
                        @"TestAllTypes_NestedEnum");

  // Foreign Enum
  fieldDescriptorWithName = [descriptor fieldWithName:@"optionalForeignEnum"];
  XCTAssertNotNil(fieldDescriptorWithName);
  fieldDescriptorWithNumber = [descriptor fieldWithNumber:22];
  XCTAssertNotNil(fieldDescriptorWithNumber);
  XCTAssertEqual(fieldDescriptorWithName, fieldDescriptorWithNumber);
  XCTAssertNotNil(fieldDescriptorWithNumber.enumDescriptor);
  XCTAssertEqualObjects(fieldDescriptorWithNumber.enumDescriptor.name,
                        @"ForeignEnum");

  // Import Enum
  fieldDescriptorWithName = [descriptor fieldWithName:@"optionalImportEnum"];
  XCTAssertNotNil(fieldDescriptorWithName);
  fieldDescriptorWithNumber = [descriptor fieldWithNumber:23];
  XCTAssertNotNil(fieldDescriptorWithNumber);
  XCTAssertEqual(fieldDescriptorWithName, fieldDescriptorWithNumber);
  XCTAssertNotNil(fieldDescriptorWithNumber.enumDescriptor);
  XCTAssertEqualObjects(fieldDescriptorWithNumber.enumDescriptor.name,
                        @"ImportEnum");

  // Nested Message
  fieldDescriptorWithName = [descriptor fieldWithName:@"optionalNestedMessage"];
  XCTAssertNotNil(fieldDescriptorWithName);
  fieldDescriptorWithNumber = [descriptor fieldWithNumber:18];
  XCTAssertNotNil(fieldDescriptorWithNumber);
  XCTAssertEqual(fieldDescriptorWithName, fieldDescriptorWithNumber);
  XCTAssertNil(fieldDescriptorWithNumber.enumDescriptor);

  // Foreign Message
  fieldDescriptorWithName =
      [descriptor fieldWithName:@"optionalForeignMessage"];
  XCTAssertNotNil(fieldDescriptorWithName);
  fieldDescriptorWithNumber = [descriptor fieldWithNumber:19];
  XCTAssertNotNil(fieldDescriptorWithNumber);
  XCTAssertEqual(fieldDescriptorWithName, fieldDescriptorWithNumber);
  XCTAssertNil(fieldDescriptorWithNumber.enumDescriptor);

  // Import Message
  fieldDescriptorWithName = [descriptor fieldWithName:@"optionalImportMessage"];
  XCTAssertNotNil(fieldDescriptorWithName);
  fieldDescriptorWithNumber = [descriptor fieldWithNumber:20];
  XCTAssertNotNil(fieldDescriptorWithNumber);
  XCTAssertEqual(fieldDescriptorWithName, fieldDescriptorWithNumber);
  XCTAssertNil(fieldDescriptorWithNumber.enumDescriptor);
}

- (void)testEnumDescriptor {
  GPBEnumDescriptor *descriptor = TestAllTypes_NestedEnum_EnumDescriptor();

  NSString *enumName = [descriptor enumNameForValue:1];
  XCTAssertNotNil(enumName);
  int32_t value;
  XCTAssertTrue(
      [descriptor getValue:&value forEnumName:@"TestAllTypes_NestedEnum_Foo"]);
  XCTAssertTrue(
      [descriptor getValue:NULL forEnumName:@"TestAllTypes_NestedEnum_Foo"]);
  XCTAssertEqual(value, TestAllTypes_NestedEnum_Foo);

  enumName = [descriptor enumNameForValue:2];
  XCTAssertNotNil(enumName);
  XCTAssertTrue(
      [descriptor getValue:&value forEnumName:@"TestAllTypes_NestedEnum_Bar"]);
  XCTAssertEqual(value, TestAllTypes_NestedEnum_Bar);

  enumName = [descriptor enumNameForValue:3];
  XCTAssertNotNil(enumName);
  XCTAssertTrue(
      [descriptor getValue:&value forEnumName:@"TestAllTypes_NestedEnum_Baz"]);
  XCTAssertEqual(value, TestAllTypes_NestedEnum_Baz);

  // TextFormat
  enumName = [descriptor textFormatNameForValue:1];
  XCTAssertNotNil(enumName);
  XCTAssertTrue([descriptor getValue:&value forEnumTextFormatName:@"FOO"]);
  XCTAssertEqual(value, TestAllTypes_NestedEnum_Foo);

  // Bad values
  enumName = [descriptor enumNameForValue:0];
  XCTAssertNil(enumName);
  XCTAssertFalse([descriptor getValue:&value forEnumName:@"Unknown"]);
  XCTAssertFalse([descriptor getValue:NULL forEnumName:@"Unknown"]);
  XCTAssertFalse([descriptor getValue:&value
                          forEnumName:@"TestAllTypes_NestedEnum_Unknown"]);
  XCTAssertFalse([descriptor getValue:NULL
                          forEnumName:@"TestAllTypes_NestedEnum_Unknown"]);
  XCTAssertFalse([descriptor getValue:NULL forEnumTextFormatName:@"Unknown"]);
  XCTAssertFalse([descriptor getValue:&value forEnumTextFormatName:@"Unknown"]);
}

- (void)testEnumValueValidator {
  GPBDescriptor *descriptor = [TestAllTypes descriptor];
  GPBFieldDescriptor *fieldDescriptor =
      [descriptor fieldWithName:@"optionalNestedEnum"];

  // Valid values
  XCTAssertTrue([fieldDescriptor isValidEnumValue:1]);
  XCTAssertTrue([fieldDescriptor isValidEnumValue:2]);
  XCTAssertTrue([fieldDescriptor isValidEnumValue:3]);
  XCTAssertTrue([fieldDescriptor isValidEnumValue:-1]);

  // Invalid values
  XCTAssertFalse([fieldDescriptor isValidEnumValue:4]);
  XCTAssertFalse([fieldDescriptor isValidEnumValue:0]);
  XCTAssertFalse([fieldDescriptor isValidEnumValue:-2]);
}

- (void)testOneofDescriptor {
  GPBDescriptor *descriptor = [TestOneof2 descriptor];

  // All fields should be listed.
  XCTAssertEqual(descriptor.fields.count, 17U);

  // There are two oneofs in there.
  XCTAssertEqual(descriptor.oneofs.count, 2U);

  GPBFieldDescriptor *fooStringField =
      [descriptor fieldWithNumber:TestOneof2_FieldNumber_FooString];
  XCTAssertNotNil(fooStringField);
  GPBFieldDescriptor *barStringField =
      [descriptor fieldWithNumber:TestOneof2_FieldNumber_BarString];
  XCTAssertNotNil(barStringField);

  // Check the oneofs to have what is expected.

  GPBOneofDescriptor *oneofFoo = [descriptor oneofWithName:@"foo"];
  XCTAssertNotNil(oneofFoo);
  XCTAssertEqual(oneofFoo.fields.count, 9U);

  // Pointer comparisons.
  XCTAssertEqual([oneofFoo fieldWithNumber:TestOneof2_FieldNumber_FooString],
                 fooStringField);
  XCTAssertEqual([oneofFoo fieldWithName:@"fooString"], fooStringField);

  GPBOneofDescriptor *oneofBar = [descriptor oneofWithName:@"bar"];
  XCTAssertNotNil(oneofBar);
  XCTAssertEqual(oneofBar.fields.count, 6U);

  // Pointer comparisons.
  XCTAssertEqual([oneofBar fieldWithNumber:TestOneof2_FieldNumber_BarString],
                 barStringField);
  XCTAssertEqual([oneofBar fieldWithName:@"barString"], barStringField);

  // Unknown oneof not found.

  XCTAssertNil([descriptor oneofWithName:@"mumble"]);
  XCTAssertNil([descriptor oneofWithName:@"Foo"]);

  // Unknown oneof item.

  XCTAssertNil([oneofFoo fieldWithName:@"mumble"]);
  XCTAssertNil([oneofFoo fieldWithNumber:666]);

  // Field exists, but not in this oneof.

  XCTAssertNil([oneofFoo fieldWithName:@"barString"]);
  XCTAssertNil([oneofFoo fieldWithNumber:TestOneof2_FieldNumber_BarString]);
  XCTAssertNil([oneofBar fieldWithName:@"fooString"]);
  XCTAssertNil([oneofBar fieldWithNumber:TestOneof2_FieldNumber_FooString]);

  // Check pointers back to the enclosing oneofs.
  // (pointer comparisions)
  XCTAssertEqual(fooStringField.containingOneof, oneofFoo);
  XCTAssertEqual(barStringField.containingOneof, oneofBar);
  GPBFieldDescriptor *bazString =
      [descriptor fieldWithNumber:TestOneof2_FieldNumber_BazString];
  XCTAssertNotNil(bazString);
  XCTAssertNil(bazString.containingOneof);
}

@end

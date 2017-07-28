<?php

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

/**
 * Defines Message, the parent class extended by all protocol message classes.
 */

namespace Google\Protobuf\Internal;

use Google\Protobuf\Internal\CodedInputStream;
use Google\Protobuf\Internal\CodedOutputStream;
use Google\Protobuf\Internal\DescriptorPool;
use Google\Protobuf\Internal\GPBLabel;
use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\GPBWire;
use Google\Protobuf\Internal\MapEntry;
use Google\Protobuf\Internal\RepeatedField;

/**
 * Parent class of all proto messages. Users should not instantiate this class
 * or extend this class or its child classes by their own.  See the comment of
 * specific functions for more details.
 */
class Message
{

    /**
     * @ignore
     */
    private $desc;

    /**
     * @ignore
     */
    public function __construct($desc = NULL)
    {
        // MapEntry message is shared by all types of map fields, whose
        // descriptors are different from each other. Thus, we cannot find a
        // specific descriptor from the descriptor pool.
        if (get_class($this) === 'Google\Protobuf\Internal\MapEntry') {
            $this->desc = $desc;
            foreach ($desc->getField() as $field) {
                $setter = $field->getSetter();
                $this->$setter($this->defaultValue($field));
            }
            return;
        }
        $pool = DescriptorPool::getGeneratedPool();
        $this->desc = $pool->getDescriptorByClassName(get_class($this));
        foreach ($this->desc->getField() as $field) {
            $setter = $field->getSetter();
            if ($field->isMap()) {
                $message_type = $field->getMessageType();
                $key_field = $message_type->getFieldByNumber(1);
                $value_field = $message_type->getFieldByNumber(2);
                switch ($value_field->getType()) {
                    case GPBType::MESSAGE:
                    case GPBType::GROUP:
                        $map_field = new MapField(
                            $key_field->getType(),
                            $value_field->getType(),
                            $value_field->getMessageType()->getClass());
                        $this->$setter($map_field);
                        break;
                    case GPBType::ENUM:
                        $map_field = new MapField(
                            $key_field->getType(),
                            $value_field->getType(),
                            $value_field->getEnumType()->getClass());
                        $this->$setter($map_field);
                        break;
                    default:
                        $map_field = new MapField(
                            $key_field->getType(),
                            $value_field->getType());
                        $this->$setter($map_field);
                        break;
                }
            } else if ($field->getLabel() === GPBLabel::REPEATED) {
                switch ($field->getType()) {
                    case GPBType::MESSAGE:
                    case GPBType::GROUP:
                        $repeated_field = new RepeatedField(
                            $field->getType(),
                            $field->getMessageType()->getClass());
                        $this->$setter($repeated_field);
                        break;
                    case GPBType::ENUM:
                        $repeated_field = new RepeatedField(
                            $field->getType(),
                            $field->getEnumType()->getClass());
                        $this->$setter($repeated_field);
                        break;
                    default:
                        $repeated_field = new RepeatedField($field->getType());
                        $this->$setter($repeated_field);
                        break;
                }
            } else if ($field->getOneofIndex() !== -1) {
                $oneof = $this->desc->getOneofDecl()[$field->getOneofIndex()];
                $oneof_name = $oneof->getName();
                $this->$oneof_name = new OneofField($oneof);
            } else if ($field->getLabel() === GPBLabel::OPTIONAL &&
                       PHP_INT_SIZE == 4) {
                switch ($field->getType()) {
                    case GPBType::INT64:
                    case GPBType::UINT64:
                    case GPBType::FIXED64:
                    case GPBType::SFIXED64:
                    case GPBType::SINT64:
                        $this->$setter("0");
                }
            }
        }
    }

    protected function readOneof($number)
    {
        $field = $this->desc->getFieldByNumber($number);
        $oneof = $this->desc->getOneofDecl()[$field->getOneofIndex()];
        $oneof_name = $oneof->getName();
        $oneof_field = $this->$oneof_name;
        if ($number === $oneof_field->getNumber()) {
            return $oneof_field->getValue();
        } else {
            return $this->defaultValue($field);
        }
    }

    protected function writeOneof($number, $value)
    {
        $field = $this->desc->getFieldByNumber($number);
        $oneof = $this->desc->getOneofDecl()[$field->getOneofIndex()];
        $oneof_name = $oneof->getName();
        $oneof_field = $this->$oneof_name;
        $oneof_field->setValue($value);
        $oneof_field->setFieldName($field->getName());
        $oneof_field->setNumber($number);
    }

    protected function whichOneof($oneof_name)
    {
        $oneof_field = $this->$oneof_name;
        $number = $oneof_field->getNumber();
        if ($number == 0) {
          return "";
        }
        $field = $this->desc->getFieldByNumber($number);
        return $field->getName();
    }

    /**
     * @ignore
     */
    private function defaultValue($field)
    {
        $value = null;

        switch ($field->getType()) {
            case GPBType::DOUBLE:
            case GPBType::FLOAT:
                return 0.0;
            case GPBType::UINT32:
            case GPBType::INT32:
            case GPBType::FIXED32:
            case GPBType::SFIXED32:
            case GPBType::SINT32:
            case GPBType::ENUM:
                return 0;
            case GPBType::INT64:
            case GPBType::UINT64:
            case GPBType::FIXED64:
            case GPBType::SFIXED64:
            case GPBType::SINT64:
                if (PHP_INT_SIZE === 4) {
                    return '0';
                } else {
                    return 0;
                }
            case GPBType::BOOL:
                return false;
            case GPBType::STRING:
            case GPBType::BYTES:
                return "";
            case GPBType::GROUP:
            case GPBType::MESSAGE:
                return null;
            default:
                user_error("Unsupported type.");
                return false;
        }
    }

    /**
     * @ignore
     */
    private static function skipField($input, $tag)
    {
        $number = GPBWire::getTagFieldNumber($tag);
        if ($number === 0) {
            throw new GPBDecodeException("Illegal field number zero.");
        }

        switch (GPBWire::getTagWireType($tag)) {
            case GPBWireType::VARINT:
                $uint64 = 0;
                if (!$input->readVarint64($uint64)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside varint.");
                }
                return;
            case GPBWireType::FIXED64:
                $uint64 = 0;
                if (!$input->readLittleEndian64($uint64)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside fixed64.");
                }
                return;
            case GPBWireType::FIXED32:
                $uint32 = 0;
                if (!$input->readLittleEndian32($uint32)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside fixed32.");
                }
                return;
            case GPBWireType::LENGTH_DELIMITED:
                $length = 0;
                if (!$input->readVarint32($length)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside length.");
                }
                $data = NULL;
                if (!$input->readRaw($length, $data)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside length delimited data.");
                }
                return;
            case GPBWireType::START_GROUP:
            case GPBWireType::END_GROUP:
                throw new GPBDecodeException("Unexpected wire type.");
            default:
                throw new GPBDecodeException("Unexpected wire type.");
        }
    }

    /**
     * @ignore
     */
    private static function parseFieldFromStreamNoTag($input, $field, &$value)
    {
        switch ($field->getType()) {
            case GPBType::DOUBLE:
                if (!GPBWire::readDouble($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside double field.");
                }
                break;
            case GPBType::FLOAT:
                if (!GPBWire::readFloat($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside float field.");
                }
                break;
            case GPBType::INT64:
                if (!GPBWire::readInt64($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside int64 field.");
                }
                break;
            case GPBType::UINT64:
                if (!GPBWire::readUint64($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside uint64 field.");
                }
                break;
            case GPBType::INT32:
                if (!GPBWire::readInt32($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside int32 field.");
                }
                break;
            case GPBType::FIXED64:
                if (!GPBWire::readFixed64($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside fixed64 field.");
                }
                break;
            case GPBType::FIXED32:
                if (!GPBWire::readFixed32($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside fixed32 field.");
                }
                break;
            case GPBType::BOOL:
                if (!GPBWire::readBool($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside bool field.");
                }
                break;
            case GPBType::STRING:
                // TODO(teboring): Add utf-8 check.
                if (!GPBWire::readString($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside string field.");
                }
                break;
            case GPBType::GROUP:
                trigger_error("Not implemented.", E_ERROR);
                break;
            case GPBType::MESSAGE:
                if ($field->isMap()) {
                    $value = new MapEntry($field->getMessageType());
                } else {
                    $klass = $field->getMessageType()->getClass();
                    $value = new $klass;
                }
                if (!GPBWire::readMessage($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside message.");
                }
                break;
            case GPBType::BYTES:
                if (!GPBWire::readString($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside bytes field.");
                }
                break;
            case GPBType::UINT32:
                if (!GPBWire::readUint32($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside uint32 field.");
                }
                break;
            case GPBType::ENUM:
                // TODO(teboring): Check unknown enum value.
                if (!GPBWire::readInt32($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside enum field.");
                }
                break;
            case GPBType::SFIXED32:
                if (!GPBWire::readSfixed32($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside sfixed32 field.");
                }
                break;
            case GPBType::SFIXED64:
                if (!GPBWire::readSfixed64($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside sfixed64 field.");
                }
                break;
            case GPBType::SINT32:
                if (!GPBWire::readSint32($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside sint32 field.");
                }
                break;
            case GPBType::SINT64:
                if (!GPBWire::readSint64($input, $value)) {
                    throw new GPBDecodeException(
                        "Unexpected EOF inside sint64 field.");
                }
                break;
            default:
                user_error("Unsupported type.");
                return false;
        }
        return true;
    }

    /**
     * @ignore
     */
    private function parseFieldFromStream($tag, $input, $field)
    {
        $value = null;

        if (is_null($field)) {
            $value_format = GPBWire::UNKNOWN;
        } elseif (GPBWire::getTagWireType($tag) ===
            GPBWire::getWireType($field->getType())) {
            $value_format = GPBWire::NORMAL_FORMAT;
        } elseif ($field->isPackable() &&
            GPBWire::getTagWireType($tag) ===
            GPBWire::WIRETYPE_LENGTH_DELIMITED) {
            $value_format = GPBWire::PACKED_FORMAT;
        } else {
            // the wire type doesn't match. Put it in our unknown field set.
            $value_format = GPBWire::UNKNOWN;
        }

        if ($value_format === GPBWire::UNKNOWN) {
            self::skipField($input, $tag);
            return;
        } elseif ($value_format === GPBWire::NORMAL_FORMAT) {
            self::parseFieldFromStreamNoTag($input, $field, $value);
        } elseif ($value_format === GPBWire::PACKED_FORMAT) {
            $length = 0;
            if (!GPBWire::readInt32($input, $length)) {
                throw new GPBDecodeException(
                    "Unexpected EOF inside packed length.");
            }
            $limit = $input->pushLimit($length);
            $getter = $field->getGetter();
            while ($input->bytesUntilLimit() > 0) {
                self::parseFieldFromStreamNoTag($input, $field, $value);
                $this->appendHelper($field, $value);
            }
            $input->popLimit($limit);
            return;
        } else {
            return;
        }

        if ($field->isMap()) {
            $this->kvUpdateHelper($field, $value->getKey(), $value->getValue());
        } else if ($field->isRepeated()) {
            $this->appendHelper($field, $value);
        } else {
            $setter = $field->getSetter();
            $this->$setter($value);
        }
    }

    /**
     * Clear all containing fields.
     * @return null.
     */
    public function clear()
    {
        foreach ($this->desc->getField() as $field) {
            $setter = $field->getSetter();
            if ($field->isMap()) {
                $message_type = $field->getMessageType();
                $key_field = $message_type->getFieldByNumber(1);
                $value_field = $message_type->getFieldByNumber(2);
                switch ($value_field->getType()) {
                    case GPBType::MESSAGE:
                    case GPBType::GROUP:
                        $map_field = new MapField(
                            $key_field->getType(),
                            $value_field->getType(),
                            $value_field->getMessageType()->getClass());
                        $this->$setter($map_field);
                        break;
                    case GPBType::ENUM:
                        $map_field = new MapField(
                            $key_field->getType(),
                            $value_field->getType(),
                            $value_field->getEnumType()->getClass());
                        $this->$setter($map_field);
                        break;
                    default:
                        $map_field = new MapField(
                            $key_field->getType(),
                            $value_field->getType());
                        $this->$setter($map_field);
                        break;
                }
            } else if ($field->getLabel() === GPBLabel::REPEATED) {
                switch ($field->getType()) {
                    case GPBType::MESSAGE:
                    case GPBType::GROUP:
                        $repeated_field = new RepeatedField(
                            $field->getType(),
                            $field->getMessageType()->getClass());
                        $this->$setter($repeated_field);
                        break;
                    case GPBType::ENUM:
                        $repeated_field = new RepeatedField(
                            $field->getType(),
                            $field->getEnumType()->getClass());
                        $this->$setter($repeated_field);
                        break;
                    default:
                        $repeated_field = new RepeatedField($field->getType());
                        $this->$setter($repeated_field);
                        break;
                }
            } else if ($field->getOneofIndex() !== -1) {
                $oneof = $this->desc->getOneofDecl()[$field->getOneofIndex()];
                $oneof_name = $oneof->getName();
                $this->$oneof_name = new OneofField($oneof);
            } else if ($field->getLabel() === GPBLabel::OPTIONAL) {
                switch ($field->getType()) {
                    case GPBType::DOUBLE   :
                    case GPBType::FLOAT    :
                        $this->$setter(0.0);
                        break;
                    case GPBType::INT32    :
                    case GPBType::FIXED32  :
                    case GPBType::UINT32   :
                    case GPBType::SFIXED32 :
                    case GPBType::SINT32   :
                    case GPBType::ENUM     :
                        $this->$setter(0);
                        break;
                    case GPBType::BOOL     :
                        $this->$setter(false);
                        break;
                    case GPBType::STRING   :
                    case GPBType::BYTES    :
                        $this->$setter("");
                        break;
                    case GPBType::GROUP    :
                    case GPBType::MESSAGE  :
                        $null = null;
                        $this->$setter($null);
                        break;
                }
                if (PHP_INT_SIZE == 4) {
                    switch ($field->getType()) {
                        case GPBType::INT64:
                        case GPBType::UINT64:
                        case GPBType::FIXED64:
                        case GPBType::SFIXED64:
                        case GPBType::SINT64:
                            $this->$setter("0");
                    }
                } else {
                    switch ($field->getType()) {
                        case GPBType::INT64:
                        case GPBType::UINT64:
                        case GPBType::FIXED64:
                        case GPBType::SFIXED64:
                        case GPBType::SINT64:
                            $this->$setter(0);
                    }
                }
            }
        }
    }

    /**
     * Merges the contents of the specified message into current message.
     *
     * This method merges the contents of the specified message into the
     * current message. Singular fields that are set in the specified message
     * overwrite the corresponding fields in the current message.  Repeated
     * fields are appended. Map fields key-value pairs are overritten.
     * Singular/Oneof sub-messages are recursively merged. All overritten
     * sub-messages are deep-copied.
     *
     * @param object $msg Protobuf message to be merged from.
     * @return null.
     */
    public function mergeFrom($msg)
    {
      if (get_class($this) !== get_class($msg)) {
          user_error("Cannot merge messages with different class.");
          return;
      }

      foreach ($this->desc->getField() as $field) {
          $setter = $field->getSetter();
          $getter = $field->getGetter();
          if ($field->isMap()) {
              if (count($msg->$getter()) != 0) {
                  $value_field = $field->getMessageType()->getFieldByNumber(2);
                  foreach ($msg->$getter() as $key => $value) {
                      if ($value_field->getType() == GPBType::MESSAGE) {
                          $klass = $value_field->getMessageType()->getClass();
                          $copy = new $klass;
                          $copy->mergeFrom($value);

                          $this->kvUpdateHelper($field, $key, $copy);
                      } else {
                          $this->kvUpdateHelper($field, $key, $value);
                      }
                  }
              }
          } else if ($field->getLabel() === GPBLabel::REPEATED) {
              if (count($msg->$getter()) != 0) {
                  foreach ($msg->$getter() as $tmp) {
                      if ($field->getType() == GPBType::MESSAGE) {
                          $klass = $field->getMessageType()->getClass();
                          $copy = new $klass;
                          $copy->mergeFrom($tmp);
                          $this->appendHelper($field, $copy);
                      } else {
                          $this->appendHelper($field, $tmp);
                      }
                  }
              }
          } else if ($field->getLabel() === GPBLabel::OPTIONAL) {
              if($msg->$getter() !== $this->defaultValue($field)) {
                  $tmp = $msg->$getter();
                  if ($field->getType() == GPBType::MESSAGE) {
                      if (is_null($this->$getter())) {
                          $klass = $field->getMessageType()->getClass();
                          $new_msg = new $klass;
                          $this->$setter($new_msg);
                      }
                      $this->$getter()->mergeFrom($tmp);
                  } else {
                      $this->$setter($tmp);
                  }
              }
          }
      }
    }

    /**
     * Parses a protocol buffer contained in a string.
     *
     * This function takes a string in the (non-human-readable) binary wire
     * format, matching the encoding output by serializeToString().
     * See mergeFrom() for merging behavior, if the field is already set in the
     * specified message.
     *
     * @param string $data Binary protobuf data.
     * @return null.
     * @throws Exception Invalid data.
     */
    public function mergeFromString($data)
    {
        $input = new CodedInputStream($data);
        $this->parseFromStream($input);
    }

    /**
     * Parses a json string to protobuf message.
     *
     * This function takes a string in the json wire format, matching the
     * encoding output by serializeToJsonString().
     * See mergeFrom() for merging behavior, if the field is already set in the
     * specified message.
     *
     * @param string $data Json protobuf data.
     * @return null.
     * @throws Exception Invalid data.
     */
    public function mergeFromJsonString($data)
    {
        $input = new RawInputStream($data);
        $this->parseFromJsonStream($input);
    }

    /**
     * @ignore
     */
    public function parseFromStream($input)
    {
        while (true) {
            $tag = $input->readTag();
            // End of input.  This is a valid place to end, so return true.
            if ($tag === 0) {
                return true;
            }

            $number = GPBWire::getTagFieldNumber($tag);
            $field = $this->desc->getFieldByNumber($number);

            $this->parseFieldFromStream($tag, $input, $field);
        }
    }

    private function convertJsonValueToProtoValue(
        $value,
        $field,
        $is_map_key = false)
    {
        if (is_null($value)) {
            return $this->defaultValue($field);
        }
        switch ($field->getType()) {
            case GPBType::MESSAGE:
                $klass = $field->getMessageType()->getClass();
                if (!is_object($value) && !is_array($value)) {
                    throw new \Exception("Expect message.");
                }
                $submsg = new $klass;
                if (!is_null($value) &&
                    $klass !== "Google\Protobuf\Any") {
                    $submsg->mergeFromJsonArray($value);
                }
                return $submsg;
            case GPBType::ENUM:
                if (is_integer($value)) {
                    return $value;
                } else {
                    $enum_value =
                        $field->getEnumType()->getValueByName($value);
                }
                if (!is_null($enum_value)) {
                    return $enum_value->getNumber();
                }
            case GPBType::STRING:
                if (!is_string($value)) {
                    throw new GPBDecodeException("Expect string");
                }
                return $value;
            case GPBType::BYTES:
                if (!is_string($value)) {
                    throw new GPBDecodeException("Expect string");
                }
                $proto_value = base64_decode($value, true);
                if ($proto_value === false) {
                    throw new GPBDecodeException(
                        "Invalid base64 characters");
                }
                return $proto_value;
            case GPBType::BOOL:
                if ($is_map_key) {
                    if ($value === "true") {
                        return true;
                    }
                    if ($value === "false") {
                        return false;
                    }
                    throw new GPBDecodeException(
                        "Bool field only accept bool value");
                }
                if (!is_bool($value)) {
                    throw new GPBDecodeException(
                        "Bool field only accept bool value");
                }
                return $value;
            case GPBType::FLOAT:
                if ($value === "Infinity") {
                    return INF;
                }
                if ($value === "-Infinity") {
                    return -INF;
                }
                if ($value === "NaN") {
                    return NAN;
                }
                return $value;
            case GPBType::DOUBLE:
                if ($value === "Infinity") {
                    return INF;
                }
                if ($value === "-Infinity") {
                    return -INF;
                }
                if ($value === "NaN") {
                    return NAN;
                }
                return $value;
            case GPBType::INT32:
                if (!is_numeric($value)) {
                   throw new GPBDecodeException(
                       "Invalid data type for int32 field");
                }
                if (bccomp($value, "2147483647") > 0) {
                   throw new GPBDecodeException(
                       "Int32 too large");
                }
                if (bccomp($value, "-2147483648") < 0) {
                   throw new GPBDecodeException(
                       "Int32 too small");
                }
                return $value;
            case GPBType::UINT32:
                if (!is_numeric($value)) {
                   throw new GPBDecodeException(
                       "Invalid data type for uint32 field");
                }
                if (bccomp($value, 4294967295) > 0) {
                    throw new GPBDecodeException(
                        "Uint32 too large");
                }
                return $value;
            case GPBType::INT64:
                if (!is_numeric($value)) {
                   throw new GPBDecodeException(
                       "Invalid data type for int64 field");
                }
                if (bccomp($value, "9223372036854775807") > 0) {
                    throw new GPBDecodeException(
                        "Int64 too large");
                }
                if (bccomp($value, "-9223372036854775808") < 0) {
                    throw new GPBDecodeException(
                        "Int64 too small");
                }
                return $value;
            case GPBType::UINT64:
                if (!is_numeric($value)) {
                   throw new GPBDecodeException(
                       "Invalid data type for int64 field");
                }
                if (bccomp($value, "18446744073709551615") > 0) {
                    throw new GPBDecodeException(
                        "Uint64 too large");
                }
                if (bccomp($value, "9223372036854775807") > 0) {
                    $value = bcsub($value, "18446744073709551616");
                }
                return $value;
            case GPBType::FIXED64:
                return $value;
            default:
                return $value;
        }
    }

    private function mergeFromJsonArray($array)
    {
        foreach ($array as $key => $value) {
            $field = $this->desc->getFieldByJsonName($key);
            if (is_null($field)) {
                $field = $this->desc->getFieldByName($key);
                if (is_null($field)) {
                    continue;
                }
            }
            $setter = $field->getSetter();
            if ($field->isMap()) {
                if (is_null($value)) {
                    continue;
                }
                $getter = $field->getGetter();
                $key_field = $field->getMessageType()->getFieldByNumber(1);
                $value_field = $field->getMessageType()->getFieldByNumber(2);
                foreach ($value as $tmp_key => $tmp_value) {
                    if (is_null($tmp_value)) {
                        throw new \Exception(
                            "Map value field element cannot be null.");
                    }
                    $proto_key =
                        $this->convertJsonValueToProtoValue(
                            $tmp_key,
                            $key_field,
                            true);
                    $proto_value =
                        $this->convertJsonValueToProtoValue(
                            $tmp_value,
                            $value_field);
                    $this->$getter()[$proto_key] = $proto_value;
                }
            } else if ($field->isRepeated()) {
                if (is_null($value)) {
                    continue;
                }
                $getter = $field->getGetter();
                foreach ($value as $tmp) {
                    if (is_null($tmp)) {
                        throw new \Exception(
                            "Repeated field elements cannot be null.");
                    }
                    $proto_value =
                        $this->convertJsonValueToProtoValue($tmp, $field);
                    $this->$getter()[] = $proto_value;
                }
            } else {
                $setter = $field->getSetter();
                $proto_value =
                    $this->convertJsonValueToProtoValue($value, $field);
                if ($field->getType() === GPBType::MESSAGE) {
                    if (is_null($proto_value)) {
                        continue;
                    }
                    $getter = $field->getGetter();
                    $submsg = $this->$getter();
                    if (!is_null($submsg)) {
                        $submsg->mergeFrom($proto_value);
                        continue;
                    }
                }
                $this->$setter($proto_value);
            }
        }
    }

    /**
     * @ignore
     */
    public function parseFromJsonStream($input)
    {
        $array = json_decode($input->getData(), JSON_BIGINT_AS_STRING);
        if (is_null($array)) {
            throw new GPBDecodeException(
                "Cannot decode json string.");
        }
        try {
            $this->mergeFromJsonArray($array);
        } catch (Exception $e) {
            throw new GPBDecodeException($e->getMessage());
        }
    }

    /**
     * @ignore
     */
    private function serializeSingularFieldToStream($field, &$output)
    {
        if (!$this->existField($field)) {
            return true;
        }
        $getter = $field->getGetter();
        $value = $this->$getter();
        if (!GPBWire::serializeFieldToStream($value, $field, true, $output)) {
            return false;
        }
        return true;
    }

    /**
     * @ignore
     */
    private function serializeRepeatedFieldToStream($field, &$output)
    {
        $getter = $field->getGetter();
        $values = $this->$getter();
        $count = count($values);
        if ($count === 0) {
            return true;
        }

        $packed = $field->getPacked();
        if ($packed) {
            if (!GPBWire::writeTag(
                $output,
                GPBWire::makeTag($field->getNumber(), GPBType::STRING))) {
                return false;
            }
            $size = 0;
            foreach ($values as $value) {
                $size += $this->fieldDataOnlyByteSize($field, $value);
            }
            if (!$output->writeVarint32($size, true)) {
                return false;
            }
        }

        foreach ($values as $value) {
            if (!GPBWire::serializeFieldToStream(
                $value,
                $field,
                !$packed,
                $output)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @ignore
     */
    private function serializeMapFieldToStream($field, $output)
    {
        $getter = $field->getGetter();
        $values = $this->$getter();
        $count = count($values);
        if ($count === 0) {
            return true;
        }

        foreach ($values as $key => $value) {
            $map_entry = new MapEntry($field->getMessageType());
            $map_entry->setKey($key);
            $map_entry->setValue($value);
            if (!GPBWire::serializeFieldToStream(
                $map_entry,
                $field,
                true,
                $output)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @ignore
     */
    private function serializeFieldToStream(&$output, $field)
    {
        if ($field->isMap()) {
            return $this->serializeMapFieldToStream($field, $output);
        } elseif ($field->isRepeated()) {
            return $this->serializeRepeatedFieldToStream($field, $output);
        } else {
            return $this->serializeSingularFieldToStream($field, $output);
        }
    }

    /**
     * @ignore
     */
    private function serializeFieldToJsonStream(&$output, $field)
    {
        $getter = $field->getGetter();
        $values = $this->$getter();
        return GPBJsonWire::serializeFieldToStream($values, $field, $output);
    }

    /**
     * @ignore
     */
    public function serializeToStream(&$output)
    {
        $fields = $this->desc->getField();
        foreach ($fields as $field) {
            if (!$this->serializeFieldToStream($output, $field)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @ignore
     */
    public function serializeToJsonStream(&$output)
    {
        $output->writeRaw("{", 1);
        $fields = $this->desc->getField();
        $first = true;
        foreach ($fields as $field) {
            if ($this->existField($field)) {
                if ($first) {
                    $first = false;
                } else {
                    $output->writeRaw(",", 1);
                }
                if (!$this->serializeFieldToJsonStream($output, $field)) {
                    return false;
                }
            }
        }
        $output->writeRaw("}", 1);
        return true;
    }

    /**
     * Serialize the message to string.
     * @return string Serialized binary protobuf data.
     */
    public function serializeToString()
    {
        $output = new CodedOutputStream($this->byteSize());
        $this->serializeToStream($output);
        return $output->getData();
    }

    /**
     * Serialize the message to json string.
     * @return string Serialized json protobuf data.
     */
    public function serializeToJsonString()
    {
        $output = new CodedOutputStream($this->jsonByteSize());
        $this->serializeToJsonStream($output);
        return $output->getData();
    }

    /**
     * @ignore
     */
    private function existField($field)
    {
        $oneof_index = $field->getOneofIndex();
        if ($oneof_index !== -1) {
            $oneof = $this->desc->getOneofDecl()[$oneof_index];
            $oneof_name = $oneof->getName();
            return $this->$oneof_name->getNumber() === $field->getNumber();
        }

        $getter = $field->getGetter();
        $values = $this->$getter();
        if ($field->isMap()) {
            return count($values) !== 0;
        } elseif ($field->isRepeated()) {
            return count($values) !== 0;
        } else {
            return $values !== $this->defaultValue($field);
        }
    }

    /**
     * @ignore
     */
    private function repeatedFieldDataOnlyByteSize($field)
    {
        $size = 0;

        $getter = $field->getGetter();
        $values = $this->$getter();
        $count = count($values);
        if ($count !== 0) {
            $size += $count * GPBWire::tagSize($field);
            foreach ($values as $value) {
                $size += $this->singularFieldDataOnlyByteSize($field);
            }
        }
    }

    /**
     * @ignore
     */
    private function fieldDataOnlyByteSize($field, $value)
    {
        $size = 0;

        switch ($field->getType()) {
            case GPBType::BOOL:
                $size += 1;
                break;
            case GPBType::FLOAT:
            case GPBType::FIXED32:
            case GPBType::SFIXED32:
                $size += 4;
                break;
            case GPBType::DOUBLE:
            case GPBType::FIXED64:
            case GPBType::SFIXED64:
                $size += 8;
                break;
            case GPBType::INT32:
            case GPBType::ENUM:
                $size += GPBWire::varint32Size($value, true);
                break;
            case GPBType::UINT32:
                $size += GPBWire::varint32Size($value);
                break;
            case GPBType::UINT64:
            case GPBType::INT64:
                $size += GPBWire::varint64Size($value);
                break;
            case GPBType::SINT32:
                $size += GPBWire::sint32Size($value);
                break;
            case GPBType::SINT64:
                $size += GPBWire::sint64Size($value);
                break;
            case GPBType::STRING:
            case GPBType::BYTES:
                $size += strlen($value);
                $size += GPBWire::varint32Size($size);
                break;
            case GPBType::MESSAGE:
                $size += $value->byteSize();
                $size += GPBWire::varint32Size($size);
                break;
            case GPBType::GROUP:
                // TODO(teboring): Add support.
                user_error("Unsupported type.");
                break;
            default:
                user_error("Unsupported type.");
                return 0;
        }

        return $size;
    }

    /**
     * @ignore
     */
    private function fieldDataOnlyJsonByteSize($field, $value)
    {
        $size = 0;

        switch ($field->getType()) {
            case GPBType::SFIXED32:
            case GPBType::SINT32:
            case GPBType::INT32:
                $size += strlen(strval($value));
                break;
            case GPBType::FIXED32:
            case GPBType::UINT32:
                if ($value < 0) {
                    $value = bcadd($value, "4294967296");
                }
                $size += strlen(strval($value));
                break;
            case GPBType::FIXED64:
            case GPBType::UINT64:
                if ($value < 0) {
                    $value = bcadd($value, "18446744073709551616");
                }
                // Intentional fall through.
            case GPBType::SFIXED64:
            case GPBType::INT64:
            case GPBType::SINT64:
                $size += 2;  // size for ""
                $size += strlen(strval($value));
                break;
            case GPBType::FLOAT:
                if (is_nan($value)) {
                    $size += strlen("NaN") + 2;
                } elseif ($value === INF) {
                    $size += strlen("Infinity") + 2;
                } elseif ($value === -INF) {
                    $size += strlen("-Infinity") + 2;
                } else {
                    $size += strlen(sprintf("%.8g", $value));
                }
                break;
            case GPBType::DOUBLE:
                if (is_nan($value)) {
                    $size += strlen("NaN") + 2;
                } elseif ($value === INF) {
                    $size += strlen("Infinity") + 2;
                } elseif ($value === -INF) {
                    $size += strlen("-Infinity") + 2;
                } else {
                    $size += strlen(sprintf("%.17g", $value));
                }
                break;
            case GPBType::ENUM:
                $enum_desc = $field->getEnumType();
                $enum_value_desc = $enum_desc->getValueByNumber($value);
                if (!is_null($enum_value_desc)) {
                    $size += 2;  // size for ""
                    $size += strlen($enum_value_desc->getName());
                } else {
                    $str_value = strval($value);
                    $size += strlen($str_value);
                }
                break;
            case GPBType::BOOL:
                if ($value) {
                    $size += 4;
                } else {
                    $size += 5;
                }
                break;
            case GPBType::STRING:
                $value = json_encode($value);
                $size += strlen($value);
                break;
            case GPBType::BYTES:
                $size += strlen(base64_encode($value));
                $size += 2;  // size for \"\"
                break;
            case GPBType::MESSAGE:
                $size += $value->jsonByteSize();
                break;
#             case GPBType::GROUP:
#                 // TODO(teboring): Add support.
#                 user_error("Unsupported type.");
#                 break;
            default:
                user_error("Unsupported type " . $field->getType());
                return 0;
        }

        return $size;
    }

    /**
     * @ignore
     */
    private function fieldByteSize($field)
    {
        $size = 0;
        if ($field->isMap()) {
            $getter = $field->getGetter();
            $values = $this->$getter();
            $count = count($values);
            if ($count !== 0) {
                $size += $count * GPBWire::tagSize($field);
                $message_type = $field->getMessageType();
                $key_field = $message_type->getFieldByNumber(1);
                $value_field = $message_type->getFieldByNumber(2);
                foreach ($values as $key => $value) {
                    $data_size = 0;
                    if ($key != $this->defaultValue($key_field)) {
                        $data_size += $this->fieldDataOnlyByteSize(
                            $key_field,
                            $key);
                        $data_size += GPBWire::tagSize($key_field);
                    }
                    if ($value != $this->defaultValue($value_field)) {
                        $data_size += $this->fieldDataOnlyByteSize(
                            $value_field,
                            $value);
                        $data_size += GPBWire::tagSize($value_field);
                    }
                    $size += GPBWire::varint32Size($data_size) + $data_size;
                }
            }
        } elseif ($field->isRepeated()) {
            $getter = $field->getGetter();
            $values = $this->$getter();
            $count = count($values);
            if ($count !== 0) {
                if ($field->getPacked()) {
                    $data_size = 0;
                    foreach ($values as $value) {
                        $data_size += $this->fieldDataOnlyByteSize($field, $value);
                    }
                    $size += GPBWire::tagSize($field);
                    $size += GPBWire::varint32Size($data_size);
                    $size += $data_size;
                } else {
                    $size += $count * GPBWire::tagSize($field);
                    foreach ($values as $value) {
                        $size += $this->fieldDataOnlyByteSize($field, $value);
                    }
                }
            }
        } elseif ($this->existField($field)) {
            $size += GPBWire::tagSize($field);
            $getter = $field->getGetter();
            $value = $this->$getter();
            $size += $this->fieldDataOnlyByteSize($field, $value);
        }
        return $size;
    }

    /**
     * @ignore
     */
    private function fieldJsonByteSize($field)
    {
        $size = 0;
        if ($field->isMap()) {
            $getter = $field->getGetter();
            $values = $this->$getter();
            $count = count($values);
            if ($count !== 0) {
                $size += 5;                              // size for "\"\":{}".
                $size += strlen($field->getJsonName());  // size for field name
                $size += $count - 1;                     // size for commas
                $getter = $field->getGetter();
                $map_entry = $field->getMessageType();
                $key_field = $map_entry->getFieldByNumber(1);
                $value_field = $map_entry->getFieldByNumber(2);
                switch ($key_field->getType()) {
                case GPBType::STRING:
                case GPBType::SFIXED64:
                case GPBType::INT64:
                case GPBType::SINT64:
                case GPBType::FIXED64:
                case GPBType::UINT64:
                    $additional_quote = false;
                    break;
                default:
                    $additional_quote = true;
                }
                foreach ($values as $key => $value) {
                    if ($additional_quote) {
                        $size += 2;  // size for ""
                    }
                    $size += $this->fieldDataOnlyJsonByteSize($key_field, $key);
                    $size += $this->fieldDataOnlyJsonByteSize($value_field, $value);
                    $size += 1;  // size for :
                }
            }
        } elseif ($field->isRepeated()) {
            $getter = $field->getGetter();
            $values = $this->$getter();
            $count = count($values);
            if ($count !== 0) {
                $size += 5;                              // size for "\"\":[]".
                $size += strlen($field->getJsonName());  // size for field name
                $size += $count - 1;                     // size for commas
                $getter = $field->getGetter();
                foreach ($values as $value) {
                    $size += $this->fieldDataOnlyJsonByteSize($field, $value);
                }
            }
        } elseif ($this->existField($field)) {
            $size += 3;                              // size for "\"\":".
            $size += strlen($field->getJsonName());  // size for field name
            $getter = $field->getGetter();
            $value = $this->$getter();
            $size += $this->fieldDataOnlyJsonByteSize($field, $value);
        }
        return $size;
    }

    /**
     * @ignore
     */
    public function byteSize()
    {
        $size = 0;

        $fields = $this->desc->getField();
        foreach ($fields as $field) {
            $size += $this->fieldByteSize($field);
        }
        return $size;
    }

    private function appendHelper($field, $append_value)
    {
        $getter = $field->getGetter();
        $setter = $field->getSetter();

        $field_arr_value = $this->$getter();
        $field_arr_value[] = $append_value;

        if (!is_object($field_arr_value)) {
            $this->$setter($field_arr_value);
        }
    }

    private function kvUpdateHelper($field, $update_key, $update_value)
    {
        $getter = $field->getGetter();
        $setter = $field->getSetter();

        $field_arr_value = $this->$getter();
        $field_arr_value[$update_key] = $update_value;

        if (!is_object($field_arr_value)) {
            $this->$setter($field_arr_value);
        }
    }

    /**
     * @ignore
     */
    public function jsonByteSize()
    {
        $size = 0;

        // Size for "{}".
        $size += 2;

        $fields = $this->desc->getField();
        $count = 0;
        foreach ($fields as $field) {
            $field_size = $this->fieldJsonByteSize($field);
            $size += $field_size;
            if ($field_size != 0) {
              $count++;
            }
        }
        // size for comma
        $size += $count > 0 ? ($count - 1) : 0;
        return $size;
    }
}

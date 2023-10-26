// ignore_for_file: constant_identifier_names, non_constant_identifier_names
import 'dart:typed_data';

import 'package:noise_protocol_framework/extensions/ext_on_byte_list.dart';

const int CIPHER_KEY_LENGTH = 32;

Uint8List MAX_UINT_64 = bytesFromHex("ffffffffffffffff");
Uint8List MAX_UINT_64_MINUS_ONE = bytesFromHex("fffffffffffffffe");

Uint8List EMPTY_32_BYTES = Uint8List(32);
Uint8List EMPTY_CIPHER_KEY_LENGTH_BYTES = Uint8List(CIPHER_KEY_LENGTH);

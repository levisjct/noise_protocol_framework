import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:elliptic/elliptic.dart' as elliptic;

extension Compare on Uint8List {
  String toHex() {
    return hex.encode(toList());
  }

  bool isEqual(Uint8List other) {
    if (length != other.length) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) {
        return false;
      }
    }
    return true;
  }

  bool incrementBigEndian() {
    bool flag = false;
    Uint8List copy = Uint8List.fromList(toList());
    for (int i = length - 1; i >= 0; i--) {
      if (copy[i] == 255) {
        copy[i] = 0;
      } else {
        copy[i]++;
        flag = true;
        break;
      }
    }
    if (flag) setAll(0, copy);
    return flag;
  }

  bool incrementLittleEndian() {
    bool flag = false;
    Uint8List copy = Uint8List.fromList(toList());
    for (int i = 0; i < length; i++) {
      if (copy[i] == 255) {
        copy[i] = 0;
      } else {
        copy[i]++;
        flag = true;
        break;
      }
    }
    if (flag) setAll(0, copy);
    return flag;
  }

  Uint8List padLeft(int len, int fill) {
    assert(fill >= 0 && fill <= 255);
    if (length >= len) {
      return this;
    }
    Uint8List res = Uint8List(len);
    res.fillRange(0, len - length, fill);
    res.setAll(len - length, this);
    return res;
  }

  Uint8List padRight(int len, int fill) {
    assert(fill >= 0 && fill <= 255);
    if (length >= len) {
      return this;
    }
    Uint8List res = Uint8List(len);
    res.setAll(0, this);
    res.fillRange(length, len, fill);
    return res;
  }
}

extension ECPublicKey on Uint8List {
  bool isCompressed(elliptic.Curve curve) {
    int compressedLength = ((curve.bitSize + 7) >> 3) + 1;
    return length == compressedLength && [2, 3].contains(this[0]);
  }

  bool isUncompressed(elliptic.Curve curve) {
    int compressedLength = ((curve.bitSize + 7) >> 3);
    return length == compressedLength * 2 + 1 && 4 == this[0];
  }
}

Uint8List bytesFromHex(String hexData, {bool pad = false}) {
  assert(hexData.length % 2 == 0, "hex data: $hexData = ${hexData.length}");
  return pad
      ? Uint8List.fromList(hex.decode(hexData)).padLeft(hexData.length ~/ 2, 0)
      : Uint8List.fromList(hex.decode(hexData));
}

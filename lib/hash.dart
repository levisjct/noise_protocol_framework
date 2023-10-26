part of 'noise_protocol_framework.dart';

class NoiseHash {
  final Hash hash;
  NoiseHash(this.hash);

  Uint8List getHash(Uint8List a, Uint8List b) {
    Uint8List res = Uint8List(a.length + b.length);
    res.setAll(0, a);
    res.setAll(a.length, b);
    return Uint8List.fromList(hash.convert(res.toList()).bytes);
  }

  Uint8List hashProtocolName(Uint8List protocolName) {
    if (protocolName.length <= CIPHER_KEY_LENGTH) {
      return protocolName.padRight(CIPHER_KEY_LENGTH, 0);
    }
    return getHash(protocolName, Uint8List(0));
  }
}

part of 'noise_protocol_framework.dart';

/// A class that represents a hash function in the Noise Protocol Framework.
class NoiseHash {
  final Hash hash;

  /// Creates a new `NoiseHash` instance with the given hash function.
  NoiseHash(this.hash);

  /// Computes the hash of the concatenation of the input byte arrays.
  ///
  /// The `a` parameter is the first input byte array.
  /// The `b` parameter is the second input byte array.
  Uint8List getHash(Uint8List a, Uint8List b) {
    Uint8List res = Uint8List(a.length + b.length);
    res.setAll(0, a);
    res.setAll(a.length, b);
    return Uint8List.fromList(hash.convert(res.toList()).bytes);
  }

  /// Computes the hash of the protocol name.
  ///
  /// The `protocolName` parameter is the protocol name to hash.
  Uint8List hashProtocolName(Uint8List protocolName) {
    if (protocolName.length <= CIPHER_KEY_LENGTH) {
      return protocolName.padRight(CIPHER_KEY_LENGTH, 0);
    }
    return getHash(protocolName, Uint8List(0));
  }
}

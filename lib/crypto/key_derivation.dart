import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A class that represents a key derivation function in the Noise Protocol Framework.
class KeyDerivation {
  final SecretKey secret;

  /// Creates a new `KeyDerivation` instance with the given key.
  KeyDerivation(Uint8List key) : secret = SecretKey(key);

  /// Derives a new key with the given length and optional salt.
  ///
  /// The `length` parameter is the length of the derived key.
  /// The `salt` parameter is the optional salt to use.
  Future<List<int>> deriveKey(int length, {Uint8List? salt}) async {
    Hkdf hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: length);
    SecretKeyData secretData = await hkdf.deriveKey(
        secretKey: secret,
        nonce: salt == null || salt.isEmpty
            ? Uint8List(Hmac.sha256().macLength)
            : salt.toList());
    return secretData.bytes;
  }
}

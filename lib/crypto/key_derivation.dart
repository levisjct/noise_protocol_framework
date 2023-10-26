import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

class KeyDerivation {
  final SecretKey secret;

  KeyDerivation(Uint8List key) : secret = SecretKey(key);

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

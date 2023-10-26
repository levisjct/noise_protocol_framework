part of 'noise_protocol_framework.dart';

class SymmetricState {
  NoiseHash hash;
  CipherState cipherState;

  Uint8List h;
  Uint8List ck;

  SymmetricState(this.cipherState, this.ck, this.h, this.hash);

  static SymmetricState initializeSymmetricState(
      Uint8List protocolName, NoiseHash hash, CipherState cipherState) {
    Uint8List h = hash.hashProtocolName(protocolName);
    return SymmetricState(cipherState, h, Uint8List.fromList(h), hash);
  }

  Future<void> mixKey(Uint8List inputKeyMaterial) async {
    KeyDerivation derivator = KeyDerivation(inputKeyMaterial);
    Uint8List ckTempk = Uint8List.fromList(
        await derivator.deriveKey(CIPHER_KEY_LENGTH * 2, salt: ck));
    ck = ckTempk.sublist(0, CIPHER_KEY_LENGTH);
    cipherState.key = ckTempk.sublist(CIPHER_KEY_LENGTH);
  }

  void mixHash(Uint8List data) {
    h = hash.getHash(h, data);
  }

  Future<void> mixKeyAndHash(Uint8List inputKeyMaterial) async {
    KeyDerivation derivator = KeyDerivation(inputKeyMaterial);
    Uint8List ckTempHTempK = Uint8List.fromList(
        await derivator.deriveKey(CIPHER_KEY_LENGTH * 3, salt: ck));

    ck = ckTempHTempK.sublist(0, CIPHER_KEY_LENGTH);
    mixHash(ckTempHTempK.sublist(CIPHER_KEY_LENGTH, CIPHER_KEY_LENGTH * 2));
    cipherState.key = ckTempHTempK.sublist(CIPHER_KEY_LENGTH * 2);
  }

  Uint8List encryptAndHash(Uint8List plaintext) {
    Uint8List ciphertext = plaintext;
    if (cipherState.hasKey) {
      ciphertext = cipherState.encryptWithAd(h, plaintext);
    }
    mixHash(ciphertext);
    return ciphertext;
  }

  Uint8List decryptAndHash(Uint8List ciphertext) {
    Uint8List plaintext = ciphertext;

    if (cipherState.hasKey) {
      plaintext = cipherState.decryptWithAd(h, ciphertext);
    }
    mixHash(ciphertext);
    return plaintext;
  }

  Future<List<CipherState>> split() async {
    KeyDerivation derivator = KeyDerivation(Uint8List(0));
    Uint8List ck1ck2 = Uint8List.fromList(
        await derivator.deriveKey(CIPHER_KEY_LENGTH * 2, salt: ck));
    return cipherState.split(ck1ck2.sublist(0, CIPHER_KEY_LENGTH),
        ck1ck2.sublist(CIPHER_KEY_LENGTH));
  }
}

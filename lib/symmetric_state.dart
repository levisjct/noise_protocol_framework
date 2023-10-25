part of './noise.dart';

class SymmetricState {
  NoiseHash hash;
  CipherState cipherState;

  Uint8List h;
  Uint8List ck;

  SymmetricState(this.cipherState, this.ck, this.h, this.hash);

  static Future<SymmetricState> initializeSymmetricState(Uint8List protocolName, NoiseHash hash, CipherState cipherState) async {
    Uint8List h = await hash.hashProtocolName(protocolName);
    return SymmetricState(cipherState, h, Uint8List.fromList(h), hash);
  }

  Future<void> mixKey(Uint8List inputKeyMaterial) async {
    KeyDerivation derivator = KeyDerivation(inputKeyMaterial);
    Uint8List ckTempk = Uint8List.fromList(await derivator.deriveKey(CIPHER_KEY_LENGTH * 2, salt: ck));
    ck = ckTempk.sublist(0, CIPHER_KEY_LENGTH);
    cipherState.key = ckTempk.sublist(CIPHER_KEY_LENGTH);
  }

  Future<void> mixHash(Uint8List data) async {
    h = await hash.getHash(h, data);
  }

  Future<void> mixKeyAndHash(Uint8List inputKeyMaterial) async {
    KeyDerivation derivator = KeyDerivation(inputKeyMaterial);
    Uint8List ckTempHTempK = Uint8List.fromList(await derivator.deriveKey(CIPHER_KEY_LENGTH * 3, salt: ck));

    ck = ckTempHTempK.sublist(0, CIPHER_KEY_LENGTH);
    await mixHash(ckTempHTempK.sublist(CIPHER_KEY_LENGTH, CIPHER_KEY_LENGTH * 2));
    cipherState.key = ckTempHTempK.sublist(CIPHER_KEY_LENGTH * 2);
  }

  Future<Uint8List> encryptAndHash(Uint8List plaintext) async {
    Uint8List ciphertext = plaintext;
    if(cipherState.hasKey) {
      ciphertext = await cipherState.encryptWithAd(h, plaintext);
    }
    await mixHash(ciphertext);
    return ciphertext;
  }

  Future<Uint8List> decryptAndHash(Uint8List ciphertext) async {
    Uint8List plaintext = ciphertext;

    if(cipherState.hasKey) {
      plaintext = await cipherState.decryptWithAd(h, ciphertext);
    }
    await mixHash(ciphertext);
    return plaintext;
  }

  Future<List<CipherState>> split() async {
    KeyDerivation derivator = KeyDerivation(Uint8List(0));
    Uint8List ck1ck2 = Uint8List.fromList(await derivator.deriveKey(CIPHER_KEY_LENGTH * 2, salt: ck));
    return cipherState.split(ck1ck2.sublist(0, CIPHER_KEY_LENGTH), ck1ck2.sublist(CIPHER_KEY_LENGTH));
  }
}
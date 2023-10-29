part of 'noise_protocol_framework.dart';

/// A class that represents a symmetric state in the Noise Protocol Framework.
class SymmetricState {
  final NoiseHash hash;
  final CipherState cipherState;

  Uint8List h;
  Uint8List ck;

  /// Creates a new `SymmetricState` instance with the given cipher state, chaining key, hash value, and hash function.
  SymmetricState(this.cipherState, this.ck, this.h, this.hash);

  /// Initializes a new `SymmetricState` instance with the given protocol name, hash function, and cipher state.
  ///
  /// The `protocolName` parameter is the name of the protocol.
  /// The `hash` parameter is the hash function to use.
  /// The `cipherState` parameter is the cipher state to use.
  static SymmetricState initializeSymmetricState(
      Uint8List protocolName, NoiseHash hash, CipherState cipherState) {
    Uint8List h = hash.hashProtocolName(protocolName);
    return SymmetricState(cipherState, h, Uint8List.fromList(h), hash);
  }

  /// Mixes the input key material into the chaining key and updates the cipher state key.
  ///
  /// The `inputKeyMaterial` parameter is the input key material to mix.
  Future<void> mixKey(Uint8List inputKeyMaterial) async {
    KeyDerivation derivator = KeyDerivation(inputKeyMaterial);
    Uint8List ckTempk = Uint8List.fromList(
        await derivator.deriveKey(CIPHER_KEY_LENGTH * 2, salt: ck));
    ck = ckTempk.sublist(0, CIPHER_KEY_LENGTH);
    cipherState.key = ckTempk.sublist(CIPHER_KEY_LENGTH);
  }

  /// Mixes the input data into the hash value.
  ///
  /// The `data` parameter is the input data to mix.
  void mixHash(Uint8List data) {
    h = hash.getHash(h, data);
  }

  /// Mixes the input key material into the chaining key, updates the hash value, and updates the cipher state key.
  ///
  /// The `inputKeyMaterial` parameter is the input key material to mix.
  Future<void> mixKeyAndHash(Uint8List inputKeyMaterial) async {
    KeyDerivation derivator = KeyDerivation(inputKeyMaterial);
    Uint8List ckTempHTempK = Uint8List.fromList(
        await derivator.deriveKey(CIPHER_KEY_LENGTH * 3, salt: ck));

    ck = ckTempHTempK.sublist(0, CIPHER_KEY_LENGTH);
    mixHash(ckTempHTempK.sublist(CIPHER_KEY_LENGTH, CIPHER_KEY_LENGTH * 2));
    cipherState.key = ckTempHTempK.sublist(CIPHER_KEY_LENGTH * 2);
  }

  /// Encrypts the input plaintext with the cipher state and mixes the resulting ciphertext into the hash value.
  ///
  /// The `plaintext` parameter is the plaintext to encrypt.
  Uint8List encryptAndHash(Uint8List plaintext) {
    Uint8List ciphertext = plaintext;
    if (cipherState.hasKey) {
      ciphertext = cipherState.encryptWithAd(h, plaintext);
    }
    mixHash(ciphertext);
    return ciphertext;
  }

  /// Decrypts the input ciphertext with the cipher state and mixes the resulting plaintext into the hash value.
  ///
  /// The `ciphertext` parameter is the ciphertext to decrypt.
  Uint8List decryptAndHash(Uint8List ciphertext) {
    Uint8List plaintext = ciphertext;

    if (cipherState.hasKey) {
      plaintext = cipherState.decryptWithAd(h, ciphertext);
    }
    mixHash(ciphertext);
    return plaintext;
  }

  /// Splits the cipher state into two new cipher states using the current chaining key.
  Future<List<CipherState>> split() async {
    KeyDerivation derivator = KeyDerivation(Uint8List(0));
    Uint8List ck1ck2 = Uint8List.fromList(
        await derivator.deriveKey(CIPHER_KEY_LENGTH * 2, salt: ck));
    return cipherState.split(ck1ck2.sublist(0, CIPHER_KEY_LENGTH),
        ck1ck2.sublist(CIPHER_KEY_LENGTH));
  }
}

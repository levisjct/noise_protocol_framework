part of 'noise_protocol_framework.dart';

/// A class that represents a cipher state in the Noise Protocol Framework.
class CipherState {
  Uint8List _key;
  Uint8List _nonce;

  final BlockCipher cipher;

  /// Creates a new `CipherState` instance with an empty key and nonce and the given block cipher.
  CipherState.empty(this.cipher)
      : _key = Uint8List(CIPHER_KEY_LENGTH),
        _nonce = Uint8List(8);

  /// Creates a new `CipherState` instance with the given key, nonce, and block cipher.
  CipherState(this._key, this._nonce, this.cipher) {
    assert(_key.length == CIPHER_KEY_LENGTH);
    assert(_nonce.length == 8);
  }

  /// Returns `true` if the cipher state has a key.
  bool get hasKey => _key.isNotEmpty;

  /// Sets the nonce of the cipher state.
  ///
  /// The `nonce` parameter is the new nonce.
  set nonce(Uint8List nonce) {
    assert(nonce.length == 8);
    _nonce = nonce;
  }

  /// Sets the key of the cipher state.
  /// NOTE: nonce will be set to 0.
  ///
  /// The `key` parameter is the new key.
  set key(Uint8List key) {
    assert(key.length == CIPHER_KEY_LENGTH);
    _key = key;
    nonce = Uint8List(8);
  }

  /// Encrypts the plaintext with the given associated data and returns the ciphertext.
  ///
  /// The `ad` parameter is the associated data.
  /// The `plaintext` parameter is the plaintext to encrypt.
  Uint8List encryptWithAd(Uint8List ad, Uint8List plaintext) {
    if (_nonce.isEqual(MAX_UINT_64_MINUS_ONE)) {
      throw Exception("Nonce overflow");
    }
    Uint8List res = _encrypt(ad, plaintext);
    _nonce.incrementBigEndian();
    return res;
  }

  Uint8List _encrypt(Uint8List ad, Uint8List plaintext, {Uint8List? n}) {
    if (n != null) assert(n.length == 8);
    Uint8List nonce = Uint8List(12);
    nonce.setRange(0, 4, [0, 0, 0, 0]);
    nonce.setAll(4, n ?? _nonce);

    cipher.reset();
    cipher.init(true, AEADParameters(KeyParameter(_key), 128, nonce, ad));

    return cipher.process(plaintext);
  }

  /// Decrypts the ciphertext with the given associated data and returns the plaintext.
  ///
  /// The `ad` parameter is the associated data.
  /// The `ciphertext` parameter is the ciphertext to decrypt.
  Uint8List decryptWithAd(Uint8List ad, Uint8List ciphertext) {
    if (_nonce.isEqual(MAX_UINT_64_MINUS_ONE)) {
      throw Exception("Nonce overflow");
    }
    Uint8List res = _decrypt(ad, ciphertext);
    _nonce.incrementBigEndian();
    return res;
  }

  Uint8List _decrypt(Uint8List ad, Uint8List ciphertext) {
    Uint8List nonce = Uint8List(12);
    nonce.setRange(4, nonce.length, _nonce);

    cipher.reset();
    cipher.init(false, AEADParameters(KeyParameter(_key), 128, nonce, ad));

    return cipher.process(ciphertext);
  }

  /// Generates a new key for the cipher state.
  Future<void> reKey() async {
    _key =
        _encrypt(Uint8List(0), EMPTY_CIPHER_KEY_LENGTH_BYTES, n: MAX_UINT_64);
  }

  /// Writes a regular message with the given payload and returns the message buffer.
  ///
  /// The `payload` parameter is the payload to write.
  MessageBuffer writeMessageRegular(Uint8List payload) {
    Uint8List cipherText = encryptWithAd(Uint8List(0), payload);
    return MessageBuffer(Uint8List(0), Uint8List(0), cipherText);
  }

  /// Reads a regular message from the given message buffer and returns the payload.
  ///
  /// The `message` parameter is the message buffer to read.
  Uint8List readMessageRegular(MessageBuffer message) {
    return decryptWithAd(Uint8List(0), message.cipherText);
  }

  /// Splits the cipher state into two cipher states with the given keys.
  ///
  /// The `key1` parameter is the key for the first cipher state.
  /// The `key2` parameter is the key for the second cipher state.
  List<CipherState> split(Uint8List key1, Uint8List key2) {
    cipher.reset();
    return [
      CipherState(key1, Uint8List(8), cipher),
      CipherState(key2, Uint8List(8), cipher)
    ];
  }
}

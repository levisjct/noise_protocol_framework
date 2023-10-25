part of './noise.dart';

class CipherState /* extends ICipherState */ {
  Uint8List _key;
  Uint8List _nonce;

  final BlockCipher cipher;

  CipherState.empty(this.cipher)
      : _key = Uint8List(CIPHER_KEY_LENGTH),
        _nonce = Uint8List(8);
  CipherState(this._key, this._nonce, this.cipher) {
    assert(_key.length == CIPHER_KEY_LENGTH);
    assert(_nonce.length == 8);
  }

  bool get hasKey => _key.isNotEmpty;

  set nonce(Uint8List nonce) {
    assert(nonce.length == 8);
    _nonce = nonce;
  }

  set key(Uint8List key) {
    assert(key.length == CIPHER_KEY_LENGTH);
    _key = key;
    nonce = Uint8List(8);
  }

  Future<Uint8List> encryptWithAd(Uint8List ad, Uint8List plaintext) async {
    if (_nonce.isEqual(MAX_UINT_64_MINUS_ONE)) {
      throw Exception("Nonce overflow");
    }
    Uint8List res = await _encrypt(ad, plaintext);
    _nonce.incrementBigEndian();
    return res;
  }

  Future<Uint8List> _encrypt(Uint8List ad, Uint8List plaintext, {Uint8List? n}) async {
    if(n != null) assert(n.length == 8);
    Uint8List nonce = Uint8List(12);
    nonce.setRange(0, 4, [0, 0, 0, 0]);
    nonce.setAll(4, n ?? _nonce);

    cipher.reset();
    cipher.init(true, AEADParameters(KeyParameter(_key), 128, nonce, ad));

    return cipher.process(plaintext);
  }

  Future<Uint8List> decryptWithAd(Uint8List ad, Uint8List ciphertext) async {
    if (_nonce.isEqual(MAX_UINT_64_MINUS_ONE)) {
      throw Exception("Nonce overflow");
    }
    Uint8List res = await _decrypt(ad, ciphertext);
    _nonce.incrementBigEndian();
    return res;
  }

  Future<Uint8List> _decrypt(Uint8List ad, Uint8List ciphertext) async {
    Uint8List nonce = Uint8List(12);
    nonce.setRange(4, nonce.length, _nonce);

    cipher.reset();
    cipher.init(false, AEADParameters(KeyParameter(_key), 128, nonce, ad));

    return cipher.process(ciphertext);
  }

  Future<void> reKey() async {
    _key = await _encrypt(Uint8List(0), EMPTY_CIPHER_KEY_LENGTH_BYTES, n: MAX_UINT_64);
  }

  Future<MessageBuffer> writeMessageRegular(Uint8List payload) async {
    Uint8List cipherText = await encryptWithAd(Uint8List(0), payload);
    return MessageBuffer(Uint8List(0), Uint8List(0), cipherText);
  }

  Future<Uint8List> readMessageRegular(MessageBuffer message) async {
    return await decryptWithAd(Uint8List(0), message.cipherText);
  }

  List<CipherState> split(Uint8List key1, Uint8List key2) {
    cipher.reset();
    return [
      CipherState(key1, Uint8List(8), cipher),
      CipherState(key2, Uint8List(8), cipher)
    ];
  }
}
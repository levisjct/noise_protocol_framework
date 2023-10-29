part of '../../noise_protocol_framework.dart';

class NKPSK0HandshakeState extends IHandshakeState {
  late SymmetricState _symmetricState;
  final NoiseHash _hash;

  late Uint8List _re;
  late KeyPair _e;

  final KeyPair? _s;
  final Uint8List? _rs;
  final Uint8List _psk;

  Uint8List? prologue;

  NKPSK0HandshakeState.responder(
      this._s, this._psk, this._hash, elliptic.Curve curve,
      {this.prologue})
      : _rs = null,
        super(curve, false) {
    assert(_s != null);
  }

  NKPSK0HandshakeState.initiator(
      this._rs, this._psk, this._hash, elliptic.Curve curve,
      {this.prologue})
      : _s = null,
        super(curve, true) {
    assert(_rs != null);
  }

  @override
  void init(CipherState cipherState, String name) {
    _symmetricState = SymmetricState.initializeSymmetricState(
        Uint8List.fromList(
            name.codeUnits), // e.g.: "Noise_NKpsk0_P256_AESGCM_SHA256"
        _hash,
        cipherState);
    if (prologue != null) {
      _symmetricState.mixHash(prologue!);
    }
    if (_isInitiator) {
      _symmetricState.mixHash(_rs!);
    } else {
      _symmetricState.mixHash(_s!.publicKey);
    }
  }

  @override
  Future<Uint8List> readMessageResponder(MessageBuffer message) async {
    await _symmetricState.mixKeyAndHash(_psk);

    _re = message.ne;

    _symmetricState.mixHash(_re);
    await _symmetricState.mixKey(_re);
    Uint8List dhsre = _computeDHKey(_s!.privateKey, _re);
    await _symmetricState.mixKey(dhsre);
    return _symmetricState.decryptAndHash(message.cipherText);
  }

  @override
  Future<NoiseResponse> writeMessageResponder(Uint8List payload) async {
    _e = KeyPair.generate(curve);

    _symmetricState.mixHash(_e.publicKey);
    await _symmetricState.mixKey(_e.publicKey);

    Uint8List dhere = _computeDHKey(_e.privateKey, _re);
    await _symmetricState.mixKey(dhere);

    Uint8List ciphertext = _symmetricState.encryptAndHash(payload);
    MessageBuffer message =
        MessageBuffer(_e.publicKey, Uint8List(0), ciphertext);

    List<CipherState> ciphers = await _symmetricState.split();

    return NoiseResponse(message, ciphers[0], ciphers[1], _symmetricState.h);
  }

  @override
  Future<MessageBuffer> writeMessageInitiator(Uint8List payload) async {
    _e = KeyPair.generate(curve);
    Uint8List ne = _e.publicKey;

    await _symmetricState.mixKeyAndHash(_psk);

    _symmetricState.mixHash(ne);
    await _symmetricState.mixKey(ne);

    Uint8List dhers = _computeDHKey(_e.privateKey, _rs!);
    await _symmetricState.mixKey(dhers);

    Uint8List cipherText = _symmetricState.encryptAndHash(payload);
    MessageBuffer message = MessageBuffer(ne, Uint8List(0), cipherText);

    return message;
  }

  @override
  Future<NoiseResponse> readMessageInitiator(MessageBuffer message) async {
    _re = message.ne;

    _symmetricState.mixHash(_re);
    await _symmetricState.mixKey(_re);

    Uint8List dhere = _computeDHKey(_e.privateKey, _re);

    await _symmetricState.mixKey(dhere);

    Uint8List ciphertext = _symmetricState.decryptAndHash(message.cipherText);
    MessageBuffer res = MessageBuffer(Uint8List(0), Uint8List(0), ciphertext);

    List<CipherState> ciphers = await _symmetricState.split();

    return NoiseResponse(res, ciphers[0], ciphers[1], _symmetricState.h);
  }
}

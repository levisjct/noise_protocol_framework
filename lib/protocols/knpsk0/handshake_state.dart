part of '../../noise_protocol_framework.dart';

class KNPSK0HandshakeState extends IHandshakeState {
  late SymmetricState _symmetricState;
  final NoiseHash _hash;

  late KeyPair _e;
  late Uint8List _re;

  final KeyPair? _s;
  final Uint8List? _rs;
  final Uint8List _psk;

  Uint8List? prologue;

  KNPSK0HandshakeState.responder(
      this._rs, this._psk, this._hash, elliptic.Curve curve,
      {this.prologue})
      : _s = null,
        super(curve, false) {
    assert(_rs != null);
  }

  KNPSK0HandshakeState.initiator(
      this._s, this._psk, this._hash, elliptic.Curve curve,
      {this.prologue})
      : _rs = null,
        super(curve, true) {
    assert(_s != null);
  }

  @override
  void init(CipherState cipherState, String name) {
    _symmetricState = SymmetricState.initializeSymmetricState(
        Uint8List.fromList(
            name.codeUnits), // e.g.: Noise_KNpsk0_P256_AESGCM_SHA256
        _hash,
        cipherState);
    if (prologue != null) {
      _symmetricState.mixHash(prologue!);
    }
    if (_isInitiator) {
      _symmetricState.mixHash(_s!.publicKey);
    } else {
      _symmetricState.mixHash(_rs!);
    }
  }

  @override
  Future<Uint8List> readMessageResponder(MessageBuffer message) async {
    await _symmetricState.mixKeyAndHash(_psk);

    _re = message.ne;

    _symmetricState.mixHash(_re);
    await _symmetricState.mixKey(_re);

    return _symmetricState.decryptAndHash(message.cipherText);
  }

  @override
  Future<NoiseResponse> writeMessageResponder(Uint8List payload) async {
    _e = KeyPair.generate(curve);
    Uint8List ne = _e.publicKey;

    _symmetricState.mixHash(_e.publicKey);
    await _symmetricState.mixKey(_e.publicKey);

    Uint8List dhre = _computeDHKey(_e.privateKey, _re);
    Uint8List dhrs = _computeDHKey(_e.privateKey, _rs!);

    await _symmetricState.mixKey(dhre);
    await _symmetricState.mixKey(dhrs);

    Uint8List ciphertext = _symmetricState.encryptAndHash(payload);
    MessageBuffer message = MessageBuffer(ne, Uint8List(0), ciphertext);
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
    Uint8List dhsre = _computeDHKey(_s!.privateKey, _re);

    await _symmetricState.mixKey(dhere);
    await _symmetricState.mixKey(dhsre);

    Uint8List payload = _symmetricState.decryptAndHash(message.cipherText);

    List<CipherState> ciphers = await _symmetricState.split();

    return NoiseResponse(MessageBuffer(Uint8List(0), Uint8List(0), payload),
        ciphers[0], ciphers[1], _symmetricState.h);
  }
}

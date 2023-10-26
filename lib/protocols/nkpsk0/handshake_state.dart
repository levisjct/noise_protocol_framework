part of '../../noise_protocol_framework.dart';

class NKPSK0HandshakeState extends IHandshakeState {
  late SymmetricState _symmetricState;
  final NoiseHash _hash;

  late Uint8List _re;
  late KeyPair _e;

  final KeyPair _s;
  final Uint8List _psk;

  Uint8List? prologue;

  NKPSK0HandshakeState(this._s, this._psk, this._hash, elliptic.Curve curve,
      {this.prologue})
      : super(curve);

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
    _symmetricState.mixHash(_s.publicKey);
  }

  @override
  Future<Uint8List> readMessageResponder(MessageBuffer message) async {
    await _symmetricState.mixKeyAndHash(_psk);

    _re = message.ne;

    _symmetricState.mixHash(_re);
    await _symmetricState.mixKey(_re);
    Uint8List dhsre = _computeDHKey(_s.privateKey, _re);
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
}

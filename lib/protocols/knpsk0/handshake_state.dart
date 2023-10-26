part of '../../noise_protocol_framework.dart';

class KNPSK0HandshakeState extends IHandshakeState {
  late SymmetricState _symmetricState;
  final NoiseHash _hash;

  late KeyPair _e;
  late Uint8List _re;

  final Uint8List _rs; 
  final Uint8List _psk;
  
  Uint8List? prologue;

  KNPSK0HandshakeState(this._rs, this._psk, this._hash, elliptic.Curve curve, {this.prologue}) : super(curve);

  @override
  void init(CipherState cipherState, String name) {
    _symmetricState = SymmetricState.initializeSymmetricState(
      Uint8List.fromList(name.codeUnits), // e.g.: Noise_KNpsk0_P256_AESGCM_SHA256
      _hash,
      cipherState
    );
    if(prologue != null) {
      _symmetricState.mixHash(prologue!);
    }
    _symmetricState.mixHash(_rs);
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
    Uint8List dhrs = _computeDHKey(_e.privateKey, _rs);

    await _symmetricState.mixKey(dhre);
    await _symmetricState.mixKey(dhrs);

    Uint8List ciphertext = _symmetricState.encryptAndHash(payload);
    MessageBuffer message = MessageBuffer(ne, Uint8List(0), ciphertext);
    List<CipherState> ciphers = await _symmetricState.split();
    
    return NoiseResponse(
      message,
      ciphers[0],
      ciphers[1],
      _symmetricState.h
    );
  }
}
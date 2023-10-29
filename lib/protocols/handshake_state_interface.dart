part of '../noise_protocol_framework.dart';

class NoiseResponse {
  final MessageBuffer message;
  final CipherState cipher1;
  final CipherState cipher2;
  Uint8List h;

  NoiseResponse(this.message, this.cipher1, this.cipher2, this.h);
}

abstract class IHandshakeState {
  Future<Uint8List> readMessageResponder(MessageBuffer message);
  Future<NoiseResponse> writeMessageResponder(Uint8List payload);
  Future<NoiseResponse> readMessageInitiator(MessageBuffer message);
  Future<MessageBuffer> writeMessageInitiator(Uint8List payload);
  void init(CipherState cipherState, String name);

  final elliptic.Curve curve;
  final bool _isInitiator;
  IHandshakeState(this.curve, this._isInitiator);

  Uint8List _computeDHKey(Uint8List privateKey, Uint8List publicKey) {
    return Uint8List.fromList(ecdh.computeSecret(
        elliptic.PrivateKey.fromBytes(curve, privateKey.toList()),
        publicKey.isCompressed(curve)
            ? curve.compressedHexToPublicKey(publicKey.toHex())
            : curve.hexToPublicKey(publicKey.toHex())));
  }

  static Uint8List uncompressPublicKey(
      Uint8List publicKey, elliptic.Curve curve) {
    return bytesFromHex(curve
        .publicKeyToHex(curve.compressedHexToPublicKey(publicKey.toHex())));
  }
}

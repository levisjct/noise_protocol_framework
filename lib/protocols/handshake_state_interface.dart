part of '../noise_protocol_framework.dart';

/// A class that represents a response in the Noise Protocol Framework.
class NoiseResponse {
  final MessageBuffer message;
  final CipherState cipher1;
  final CipherState cipher2;
  Uint8List h;

  /// Creates a new `NoiseResponse` instance with the given message, cipher states, and hash.
  NoiseResponse(this.message, this.cipher1, this.cipher2, this.h);
}

/// An interface that represents a handshake state in the Noise Protocol Framework.
abstract class IHandshakeState {
  /// Reads a message from the responder and returns the payload.
  ///
  /// The `message` parameter is the message buffer to read.
  Future<Uint8List> readMessageResponder(MessageBuffer message);

  /// Writes a message to the responder and returns the response.
  ///
  /// The `payload` parameter is the payload to write.
  Future<NoiseResponse> writeMessageResponder(Uint8List payload);

  /// Reads a message from the initiator and returns the response.
  ///
  /// The `message` parameter is the message buffer to read.
  Future<NoiseResponse> readMessageInitiator(MessageBuffer message);

  /// Writes a message to the initiator and returns the message buffer.
  ///
  /// The `payload` parameter is the payload to write.
  Future<MessageBuffer> writeMessageInitiator(Uint8List payload);

  /// Initializes the handshake state with the given cipher state and name.
  ///
  /// The `cipherState` parameter is the cipher state to use.
  /// The `name` parameter is the name of the handshake pattern.
  void init(CipherState cipherState, String name);

  final elliptic.Curve curve;
  final bool _isInitiator;

  /// Creates a new `IHandshakeState` instance with the given curve and initiator flag.
  IHandshakeState(this.curve, this._isInitiator);

  /// Computes the Diffie-Hellman key with the given private and public keys.
  ///
  /// The `privateKey` parameter is the private key.
  /// The `publicKey` parameter is the public key.
  Uint8List _computeDHKey(Uint8List privateKey, Uint8List publicKey) {
    return Uint8List.fromList(ecdh.computeSecret(
        elliptic.PrivateKey.fromBytes(curve, privateKey.toList()),
        publicKey.isCompressed(curve)
            ? curve.compressedHexToPublicKey(publicKey.toHex())
            : curve.hexToPublicKey(publicKey.toHex())));
  }

  /// Uncompresses the given compressed public key for the given curve.
  ///
  /// The `publicKey` parameter is the compressed public key to uncompress.
  static Uint8List uncompressPublicKey(
      Uint8List publicKey, elliptic.Curve curve) {
    return bytesFromHex(curve
        .publicKeyToHex(curve.compressedHexToPublicKey(publicKey.toHex())));
  }
}

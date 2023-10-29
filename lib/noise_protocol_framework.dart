library noise_protocol_framework;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:elliptic/ecdh.dart' as ecdh;
import 'package:elliptic/elliptic.dart' as elliptic;

import 'package:noise_protocol_framework/constants/noise_constants.dart';
import 'package:noise_protocol_framework/extensions/ext_on_byte_list.dart';
import 'package:noise_protocol_framework/crypto/key_derivation.dart';

part './protocols/knpsk0/handshake_state.dart';
part './protocols/nkpsk0/handshake_state.dart';
part './protocols/handshake_state_interface.dart';

part './hash.dart';
part './keypair.dart';
part './cipher_state.dart';
part './message_buffer.dart';
part './symmetric_state.dart';

/// A class that represents a Noise Protocol instance.
class NoiseProtocol {
  int _messageCounter;
  final IHandshakeState _handshakeState;
  bool isInitialized = false;

  late CipherState _cipher1;
  late CipherState _cipher2;

  CipherState get cipher1 => _cipher1;
  CipherState get cipher2 => _cipher2;

  /// Creates a new `NoiseProtocol` instance with a custom handshake state.
  ///
  /// The `handshakeState` parameter must be an instance of a class that implements the `IHandshakeState` interface.
  NoiseProtocol.custom(this._handshakeState) : _messageCounter = 0;

  /// Creates a new `NoiseProtocol` instance with the KNPSK0 responder handshake pattern.
  ///
  /// The `rs` parameter is the initiator's static public key.
  /// The `psk` parameter is the pre-shared key.
  /// The `hash` parameter is the hash function to use.
  /// The `curve` parameter is the elliptic curve to use.
  /// The `prologue` parameter is an optional byte sequence that is included in the handshake.
  NoiseProtocol.getKNPSK0Responder(
      Uint8List rs, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = KNPSK0HandshakeState.responder(
            IHandshakeState.uncompressPublicKey(rs, curve), psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  /// Creates a new `NoiseProtocol` instance with the KNPSK0 initiator handshake pattern.
  ///
  /// The `s` parameter is the initiator's static key pair.
  /// The `psk` parameter is the pre-shared key.
  /// The `hash` parameter is the hash function to use.
  /// The `curve` parameter is the elliptic curve to use.
  /// The `prologue` parameter is an optional byte sequence that is included in the handshake.
  NoiseProtocol.getKNPSK0Initiator(
      KeyPair s, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = KNPSK0HandshakeState.initiator(s, psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  /// Creates a new `NoiseProtocol` instance with the NKPSK0 responder handshake pattern.
  ///
  /// The `s` parameter is the responder's static key pair.
  /// The `psk` parameter is the pre-shared key.
  /// The `hash` parameter is the hash function to use.
  /// The `curve` parameter is the elliptic curve to use.
  /// The `prologue` parameter is an optional byte sequence that is included in the handshake.
  NoiseProtocol.getNKPSK0Responder(
      KeyPair s, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = NKPSK0HandshakeState.responder(s, psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  /// Creates a new `NoiseProtocol` instance with the NKPSK0 initiator handshake pattern.
  ///
  /// The `rs` parameter is the responder's static public key.
  /// The `psk` parameter is the pre-shared key.
  /// The `hash` parameter is the hash function to use.
  /// The `curve` parameter is the elliptic curve to use.
  /// The `prologue` parameter is an optional byte sequence that is included in the handshake.
  NoiseProtocol.getNKPSK0Initiator(
      Uint8List rs, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = NKPSK0HandshakeState.initiator(rs, psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  /// Initializes the `NoiseProtocol` instance with the given cipher state and name.
  ///
  /// The `cipherState` parameter is the cipher state to use.
  /// The `name` parameter is the name of the protocol. e.g: "Noise_XX_25519_AESGCM_SHA256".
  void initialize(CipherState cipherState, String name) {
    _handshakeState.init(cipherState, name);
    isInitialized = true;
  }

  /// Reads a message from the given message buffer.
  ///
  /// The `message` parameter is the message buffer to read from.
  Future<Uint8List> readMessage(MessageBuffer message) async {
    if (!isInitialized) {
      throw Exception("NoiseProtocol is not initialized");
    }
    Uint8List res;
    if (_messageCounter == 0 && !_handshakeState._isInitiator) {
      res = await _handshakeState.readMessageResponder(message);
    } else if (_messageCounter == 1 && _handshakeState._isInitiator) {
      NoiseResponse noiseRes =
          await _handshakeState.readMessageInitiator(message);
      _cipher1 = noiseRes.cipher2;
      _cipher2 = noiseRes.cipher1;
      res = noiseRes.message.cipherText;
    } else if (_messageCounter <= 1) {
      throw Exception("Invalid message counter");
    } else {
      res = _cipher1.readMessageRegular(message);
    }
    _messageCounter++;
    return res;
  }

  /// Sends a message with the given payload.
  ///
  /// The `payload` parameter is the payload to send.
  Future<MessageBuffer> sendMessage(Uint8List payload) async {
    if (!isInitialized) {
      throw Exception("NoiseProtocol is not initialized");
    }
    MessageBuffer res;
    if (_messageCounter == 1 && !_handshakeState._isInitiator) {
      NoiseResponse writeResponse =
          await _handshakeState.writeMessageResponder(payload);
      _cipher1 = writeResponse.cipher1;
      _cipher2 = writeResponse.cipher2;

      res = writeResponse.message;
    } else if (_messageCounter == 0 && _handshakeState._isInitiator) {
      res = await _handshakeState.writeMessageInitiator(payload);
    } else if (_messageCounter <= 1) {
      throw Exception("Invalid message counter");
    } else {
      res = _cipher2.writeMessageRegular(payload);
    }
    _messageCounter++;
    return res;
  }
}

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

class NoiseProtocol {
  int _messageCounter;
  final IHandshakeState _handshakeState;

  late CipherState _cipher1;
  late CipherState _cipher2;

  CipherState get cipher1 => _cipher1;
  CipherState get cipher2 => _cipher2;

  NoiseProtocol.custom(this._handshakeState) : _messageCounter = 0;

  NoiseProtocol.getKNPSK0Responder(
      Uint8List rs, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = KNPSK0HandshakeState.responder(
            IHandshakeState.uncompressPublicKey(rs, curve), psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  NoiseProtocol.getKNPSK0Initiator(
      KeyPair s, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = KNPSK0HandshakeState.initiator(s, psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  NoiseProtocol.getNKPSK0Responder(
      KeyPair s, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = NKPSK0HandshakeState.responder(s, psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  NoiseProtocol.getNKPSK0Initiator(
      Uint8List rs, Uint8List psk, NoiseHash hash, elliptic.Curve curve,
      {Uint8List? prologue})
      : _messageCounter = 0,
        _handshakeState = NKPSK0HandshakeState.initiator(rs, psk, hash, curve,
            prologue: prologue) {
    assert(psk.length == 32);
  }

  void initialize(CipherState cipherState, String name) {
    _handshakeState.init(cipherState, name);
  }

  Future<Uint8List> readMessage(MessageBuffer message) async {
    Uint8List res;
    if (_messageCounter == 0 && !_handshakeState._isInitiator) {
      res = await _handshakeState.readMessageResponder(message);
    } else if (_messageCounter == 1 && _handshakeState._isInitiator) {
      NoiseResponse noiseRes =
          await _handshakeState.readMessageInitiator(message);
      _cipher1 = noiseRes.cipher1;
      _cipher2 = noiseRes.cipher2;
      res = noiseRes.message.cipherText;
    } else if (_messageCounter <= 1) {
      throw Exception("Invalid message counter");
    } else {
      res = _cipher1.readMessageRegular(message);
    }
    _messageCounter++;
    return res;
  }

  Future<MessageBuffer> sendMessage(Uint8List payload) async {
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

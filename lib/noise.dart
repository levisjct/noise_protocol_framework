library noise;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:elliptic/ecdh.dart' as ecdh;
import 'package:elliptic/elliptic.dart' as elliptic;

import 'package:noise/constants/noise_constants.dart';
import 'package:noise/extensions/ext_on_byte_list.dart';
import 'package:noise/crypto/key_derivation.dart';

part './protocols/knpsk0/handshake_state.dart';
part './protocols/nkpsk0/handshake_state.dart';
part './protocols/handshake_state_interface.dart';

part './hash.dart';
part './keypair.dart';
part './cipher_state.dart';
part './message_buffer.dart';
part './symmetric_state.dart';

class NoiseProtocolResponder {
  int _messageCounter;
  final IHandshakeState _handshakeState;

  late CipherState _cipher1;
  late CipherState _cipher2;

  CipherState get cipher1 => _cipher1;
  CipherState get cipher2 => _cipher2;

  NoiseProtocolResponder.custom(this._handshakeState) :
    _messageCounter = 0;

  NoiseProtocolResponder.getKNPSK0(Uint8List rs, Uint8List psk, NoiseHash hash, elliptic.Curve curve, {Uint8List? prologue}) : 
    _messageCounter = 0,
    _handshakeState = KNPSK0HandshakeState(
      IHandshakeState.uncompressPublicKey(rs, curve), 
      psk, 
      hash,
      curve,
      prologue: prologue
    ) {
    assert(psk.length == 32);
  }

  NoiseProtocolResponder.getNKPSK0(KeyPair s, Uint8List psk, NoiseHash hash, elliptic.Curve curve, {Uint8List? prologue}): 
    _messageCounter = 0, 
    _handshakeState = NKPSK0HandshakeState(s, psk, hash, curve, prologue: prologue) {
    assert(psk.length == 32);
  }

  Future<void> initialize(CipherState cipherState, String name) async {
    await _handshakeState.init(cipherState, name);
  }

  Future<Uint8List> readMessage(MessageBuffer message) async {
    Uint8List res;
    if(_messageCounter == 0){
      res = await _handshakeState.readMessageResponder(message);
    } else {
      res = await _cipher1.readMessageRegular(message);
    }
    _messageCounter++;
    return res;
  }

  Future<MessageBuffer> sendMessage(Uint8List payload) async {
    MessageBuffer res;
    if(_messageCounter == 1){
      NoiseResponse writeResponse = await _handshakeState.writeMessageResponder(payload);
      _cipher1 = writeResponse.cipher1;
      _cipher2 = writeResponse.cipher2;
      
      res = writeResponse.message;
    } else {
      res = await _cipher2.writeMessageRegular(payload);
    }
    _messageCounter++;
    return res;
  }
}

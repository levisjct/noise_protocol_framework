import 'dart:typed_data';
import 'package:noise_protocol_framework/extensions/ext_on_byte_list.dart';
import 'package:noise_protocol_framework/noise_protocol_framework.dart';
import 'package:elliptic/elliptic.dart';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart' show GCMBlockCipher, BlockCipher;

Future<void> knpsk0(Curve curve, Uint8List psk, String name) async {
  // Initialize the handshake state for the initiator
  KeyPair initiatorStatic = KeyPair.generate(curve);
  NoiseProtocol initiator = NoiseProtocol.getKNPSK0Initiator(
      initiatorStatic, psk, NoiseHash(sha256), curve);
  initiator.initialize(
      CipherState.empty(GCMBlockCipher(BlockCipher("AES"))), name);

  // Initialize the handshake state for the responder
  NoiseProtocol responder = NoiseProtocol.getKNPSK0Responder(
      bytesFromHex(curve.publicKeyToCompressedHex(
          PublicKey.fromHex(curve, initiatorStatic.publicKey.toHex()))),
      psk,
      NoiseHash(sha256),
      curve);
  responder.initialize(
      CipherState.empty(GCMBlockCipher(BlockCipher("AES"))), name);

  var initiatorMessage1 = await initiator.sendMessage(Uint8List(0));
  var responderMessage1 = await responder.readMessage(initiatorMessage1);
  assert(responderMessage1.isEmpty);
  var responderMessage2 = await responder.sendMessage(Uint8List(0));
  var initiatorMessage2 = await initiator.readMessage(responderMessage2);
  assert(initiatorMessage2.isEmpty);

  // Encrypt and send a message from the initiator to the responder
  final plaintext = Uint8List.fromList('Hello, responder!'.codeUnits);
  final ciphertext = await initiator.sendMessage(plaintext);

  final response = await responder.readMessage(ciphertext);
  print('Responder received message: ${String.fromCharCodes(response)}');

  // Encrypt and send a message from the responder to the initiator
  final plaintext2 = Uint8List.fromList('Hello, initiator!'.codeUnits);
  final ciphertext2 = await responder.sendMessage(plaintext2);

  final response2 = await initiator.readMessage(ciphertext2);
  print('Initiator received message: ${String.fromCharCodes(response2)}');
}

Future<void> nkpsk0(Curve curve, Uint8List psk, String name) async {
  // Initialize the handshake state for the initiator
  KeyPair responderStatic = KeyPair.generate(curve);
  NoiseProtocol initiator = NoiseProtocol.getNKPSK0Initiator(
      bytesFromHex(responderStatic.publicKey.toHex()), 
      psk, 
      NoiseHash(sha256), 
      curve
    );
  initiator.initialize(
      CipherState.empty(GCMBlockCipher(BlockCipher("AES"))), name);

  // Initialize the handshake state for the responder
  NoiseProtocol responder = NoiseProtocol.getNKPSK0Responder(
      responderStatic,
      psk,
      NoiseHash(sha256),
      curve);
  responder.initialize(
      CipherState.empty(GCMBlockCipher(BlockCipher("AES"))), name);

  var initiatorMessage1 = await initiator.sendMessage(Uint8List(0));
  var responderMessage1 = await responder.readMessage(initiatorMessage1);
  assert(responderMessage1.isEmpty);
  var responderMessage2 = await responder.sendMessage(Uint8List(0));
  var initiatorMessage2 = await initiator.readMessage(responderMessage2);
  assert(initiatorMessage2.isEmpty);

  // Encrypt and send a message from the initiator to the responder
  final plaintext = Uint8List.fromList('Hello, responder!'.codeUnits);
  final ciphertext = await initiator.sendMessage(plaintext);
  // print("initiator ciphered text ${String.fromCharCodes(ciphertext.cipherText)}");
  final response = await responder.readMessage(ciphertext);
  print('Responder received message: ${String.fromCharCodes(response)}');

  // Encrypt and send a message from the responder to the initiator
  final plaintext2 = Uint8List.fromList('Hello, initiator!'.codeUnits);
  final ciphertext2 = await responder.sendMessage(plaintext2);
  // print("responder ciphered text ${String.fromCharCodes(ciphertext2.cipherText)}");

  final response2 = await initiator.readMessage(ciphertext2);
  print('Initiator received message: ${String.fromCharCodes(response2)}');
}

void main() async {
  Curve curve = getP256();
  Uint8List psk = bytesFromHex(
      "688c945cc5b07669ee30be7cbf6ac66cf7b9f53e3a8a787304be1d378ede0183");

  await knpsk0(curve, psk, "Noise_KNpsk0_P256_AESGCM_SHA256");
  await nkpsk0(curve, psk, "Noise_NKpsk0_P256_AESGCM_SHA256");
}

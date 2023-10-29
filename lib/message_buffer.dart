part of 'noise_protocol_framework.dart';

/// A class that represents a message buffer in the Noise Protocol Framework.
class MessageBuffer {
  final Uint8List ne;
  final Uint8List ns;
  final Uint8List cipherText;

  /// Creates a new `MessageBuffer` instance with the given ephemeral nonce, static nonce, and ciphertext.
  MessageBuffer(this.ne, this.ns, this.cipherText);
}

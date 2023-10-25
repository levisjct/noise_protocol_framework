part of './noise.dart';

class MessageBuffer {
  final Uint8List ne;
  final Uint8List ns;
  final Uint8List cipherText;

  MessageBuffer(this.ne, this.ns, this.cipherText);
}
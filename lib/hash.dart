part of './noise.dart';

class NoiseHash {
  final Hash hash;
  NoiseHash(this.hash);

  Future<Uint8List> getHash(Uint8List a, Uint8List b) async {
    Uint8List res = Uint8List(a.length + b.length);
    res.setAll(0, a);
    res.setAll(a.length, b);
    return Uint8List.fromList((await hash.convert(res.toList())).bytes);
  }

  Future<Uint8List> hashProtocolName(Uint8List protocolName) async {
    if(protocolName.length <= CIPHER_KEY_LENGTH) return protocolName.padRight(CIPHER_KEY_LENGTH, 0);
    return await getHash(protocolName, Uint8List(0));
  }
}
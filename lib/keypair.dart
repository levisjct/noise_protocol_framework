part of './noise.dart';

class KeyPair {
  final Uint8List _publicKey;
  final Uint8List _privateKey;
  final elliptic.Curve curve;

  KeyPair._(this._publicKey, this._privateKey, this.curve);
  
  KeyPair.fromMap(Map<String, String> json, elliptic.Curve curve) : this._(
    bytesFromHex(json['publicKey']!),
    bytesFromHex(json['privateKey']!),
    curve
  );

  Map<String, String> toMap() => {
    'publicKey': _publicKey.toHex(),
    'privateKey': _privateKey.toHex(),
    'curve': curve.name
  };

  Uint8List get publicKey => Uint8List.fromList(_publicKey.toList());
  Uint8List get privateKey => Uint8List.fromList(_privateKey.toList());

  static Future<KeyPair> generate(elliptic.Curve curve) async {
    elliptic.PrivateKey prk = curve.generatePrivateKey();
    return KeyPair._(
      bytesFromHex(curve.publicKeyToHex(prk.publicKey)),
      Uint8List.fromList(prk.bytes),
      curve
    );
  }
}
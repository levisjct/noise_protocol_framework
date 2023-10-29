part of 'noise_protocol_framework.dart';

/// A class that represents a key pair in the Noise Protocol Framework.
class KeyPair {
  final Uint8List _publicKey;
  final Uint8List _privateKey;
  final elliptic.Curve curve;

  /// Creates a new `KeyPair` instance with the given public key, private key, and elliptic curve.
  KeyPair._(this._publicKey, this._privateKey, this.curve);

  /// Creates a new `KeyPair` instance from a map with the public key, private key, and elliptic curve.
  ///
  /// The `json` parameter is a map with the public key, private key, and elliptic curve.
  /// The `curve` parameter is the elliptic curve to use.
  KeyPair.fromMap(Map<String, String> json, elliptic.Curve curve)
      : this._(bytesFromHex(json['publicKey']!),
            bytesFromHex(json['privateKey']!), curve);

  /// Converts the `KeyPair` instance to a map with the public key, private key, and elliptic curve.
  Map<String, String> toMap() => {
        'publicKey': _publicKey.toHex(),
        'privateKey': _privateKey.toHex(),
        'curve': curve.name
      };

  /// Returns a copy of the public key.
  Uint8List get publicKey => Uint8List.fromList(_publicKey.toList());

  /// Returns a copy of the private key.
  Uint8List get privateKey => Uint8List.fromList(_privateKey.toList());

  /// Generates a new `KeyPair` instance with the given elliptic curve.
  ///
  /// The `curve` parameter is the elliptic curve to use.
  static KeyPair generate(elliptic.Curve curve) {
    elliptic.PrivateKey prk = curve.generatePrivateKey();
    return KeyPair._(bytesFromHex(curve.publicKeyToHex(prk.publicKey)),
        Uint8List.fromList(prk.bytes), curve);
  }
}

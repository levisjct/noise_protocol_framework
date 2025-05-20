# noise_protocol_framework

`noise_protocol_framework` is a pure Dart library that provides an easy-to-use implementation of the Noise Protocol Framework. The Noise Protocol Framework is a set of cryptographic protocols that can be used to establish secure communication channels between two parties.

This implementation draws inspiration from [Yawning](https://github.com/Yawning/nyquist)'s Noise Protocol Framework, which is written in Golang.

For more information about Noise Protocol Framework please refer to [the official Noise Protocol Framework specs website](https://noiseprotocol.org/noise.html).

## Features

- Implements the Noise Protocol Framework.
- Supports various handshake patterns and cipher suites, including custom patterns.
- Provides a simple API for encrypting and decrypting messages.
- Supports pre-shared keys and static keys.

This package has been created with the best effort to ensure its reliability and efficiency.

## Usage

To use `noise_protocol_framework`, add it to your `pubspec.yaml` file:

```yaml
dependencies:
  noise_protocol_framework: ^1.1.0
```

Then, import the library:

`import 'package:noise_protocol_framework/noise_protocol_framework.dart';`

You can use the library to establish a secure communication channel between two parties.

For more information on how to use the library, please refer to [the API documentation](https://pub.dev/documentation/noise_protocol_framework/latest/).

## Contributing
Contributions are welcome! Please read [the contributing guide](CONTRIBUTE.md) for more information.

## License
noise_protocol_framework is released under the MIT License. See [LICENSE](LICENSE) for more information.
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:web3dart/crypto.dart';
import 'package:bech32/bech32.dart';
import 'package:crypto/crypto.dart';
class RandomBridge implements SecureRandom {
  Random dartRandom;

  RandomBridge(this.dartRandom);

  @override
  String get algorithmName => 'DartRandom';

  @override
  BigInt nextBigInteger(int bitLength) {
    final fullBytes = bitLength ~/ 8;
    final remainingBits = bitLength % 8;

    // Generate a number from the full bytes. Then, prepend a smaller number
    // covering the remaining bits.
    final main = bytesToInt(nextBytes(fullBytes));
    final additional = dartRandom.nextInt(1 << remainingBits);
    return main + (BigInt.from(additional) << (fullBytes * 8));
  }

  @override
  Uint8List nextBytes(int count) {
    final list = Uint8List(count);

    for (var i = 0; i < list.length; i++) {
      list[i] = nextUint8();
    }

    return list;
  }

  @override
  int nextUint16() => dartRandom.nextInt(1 << 16);

  @override
  int nextUint32() => dartRandom.nextInt(1 << 32);

  @override
  int nextUint8() => dartRandom.nextInt(1 << 8);

  @override
  void seed(CipherParameters params) {
    // ignore, dartRandom will already be seeded if wanted
  }
}

const int _shaBytes = 256 ~/ 8;

final ECDomainParameters _params = ECCurve_secp256k1();
final BigInt _halfCurveOrder = _params.n >> 1;

/// Generates a public key for the given private key using the ecdsa curve which
/// Ethereum uses.
Uint8List privateKeyBytesToPublic(Uint8List privateKey, bool compressed) {
  return privateKeyToPublic(bytesToInt(privateKey), compressed);
}

/// Generates a public key for the given private key using the ecdsa curve which
/// Ethereum uses.
Uint8List privateKeyToPublic(BigInt privateKey, bool compressed) {
  final p = _params.G * privateKey;

  return Uint8List.view(p.getEncoded(compressed).buffer);
}

/// Generates a new private key using the random instance provided. Please make
/// sure you're using a cryptographically secure generator.
BigInt generateNewPrivateKey(Random random) {
  final generator = ECKeyGenerator();

  final keyParams = ECKeyGeneratorParameters(_params);

  generator.init(ParametersWithRandom(keyParams, RandomBridge(random)));

  final key = generator.generateKeyPair();
  final privateKey = key.privateKey as ECPrivateKey;
  return privateKey.d;
}

/// Constructs the Ethereum address associated with the given public key by
/// taking the lower 160 bits of the key's sha3 hash.
Uint8List publicKeyToAddress(Uint8List publicKey) {
  assert(publicKey.length == 64);

  final hashed = sha3digest.process(publicKey);
  return Uint8List.view(hashed.buffer, _shaBytes - 20);
}

/// Signatures used to sign Ethereum transactions and messages.
class MsgSignature {
  final BigInt r;
  final BigInt s;
  final int v;

  MsgSignature(this.r, this.s, this.v);
}


BigInt _recoverFromSignature(
    int recId, ECSignature sig, Uint8List msg, ECDomainParameters params) {
  final n = params.n;
  final i = BigInt.from(recId ~/ 2);
  final x = sig.r + (i * n);

  //Parameter q of curve
  final prime = BigInt.parse(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
      radix: 16);
  if (x.compareTo(prime) >= 0) return null;

  final R = _decompressKey(x, (recId & 1) == 1, params.curve);
  if (!(R * n).isInfinity) return null;

  final e = bytesToInt(msg);

  final eInv = (BigInt.zero - e) % n;
  final rInv = sig.r.modInverse(n);
  final srInv = (rInv * sig.s) % n;
  final eInvrInv = (rInv * eInv) % n;

  final q = (params.G * eInvrInv) + (R * srInv);

  final bytes = q.getEncoded(false);
  return bytesToInt(bytes.sublist(1));
}

ECPoint _decompressKey(BigInt xBN, bool yBit, ECCurve c) {
  List<int> x9IntegerToBytes(BigInt s, int qLength) {
    //https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x9/X9IntegerConverter.java#L45
    final bytes = intToBytes(s);

    if (qLength < bytes.length) {
      return bytes.sublist(0, bytes.length - qLength);
    } else if (qLength > bytes.length) {
      final tmp = List<int>.filled(qLength, 0);

      final offset = qLength - bytes.length;
      for (var i = 0; i < bytes.length; i++) {
        tmp[i + offset] = bytes[i];
      }

      return tmp;
    }

    return bytes;
  }

  final compEnc = x9IntegerToBytes(xBN, 1 + ((c.fieldSize + 7) ~/ 8));
  compEnc[0] = yBit ? 0x03 : 0x02;
  return c.decodePoint(compEnc);
}

class FullBechCodec extends Bech32Codec {
  FullBechCodec();
  List convert (data, inBits, outBits, pad) {
  var value = 0;
  var bits = 0;
  var maxV = (1 << outBits) - 1;

  List<int> result = [];
  for (var i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i];
    bits += inBits;

    while (bits >= outBits) {
      bits -= outBits;
      result.add((value >> bits) & maxV);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.add((value << (outBits - bits)) & maxV);
    }
  } else {
    if (bits >= inBits) throw Exception('Excess padding');
    if ((value << (outBits - bits)) & maxV != null) throw Exception('Non-zero padding');
  }

  return result;
}
  List<int> toWords(bytes) {
    return convert(bytes, 8, 5, true);
  }
}


void main() {
  Map<String, String> account = {
    'address': 'nts12wt2aqu4ml78ufdg5d663e66f90rrnxxswp79a',
    'privateKey': '76a218f9bce73412d3f0523e60b627707f714d24f2956cc6fe3769ab95ade9cd'
  };
  var pKeyFull = privateKeyBytesToPublic(hexToBytes(account['privateKey']), false);
  var pKeyComp = privateKeyBytesToPublic(hexToBytes(account['privateKey']), true);
  var resSha256 = sha256.convert(pKeyComp);
  var ripemd = RIPEMD160Digest();
  var resRipemd = ripemd.process(resSha256.bytes);
  
  FullBechCodec fullCodec = FullBechCodec();

  var myList = fullCodec.toWords(resRipemd);
  print(myList);
  String bech32 = fullCodec.encode(Bech32('nts', myList));
  print(bech32);
}
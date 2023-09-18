// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Google.Protobuf;
using Nethermind.Libp2p.Core.Dto;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Buffers;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nethermind.Libp2p.Core;

/// <summary>
///     https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
/// </summary>
public class Identity
{
    private const KeyType DefaultKeyType = KeyType.Ed25519;

    public PublicKey PublicKey { get; }
    public PrivateKey? PrivateKey { get; }

    public Identity(byte[]? privateKey = default, KeyType keyType = DefaultKeyType)
    {
        if (privateKey is null)
        {
            (PrivateKey, PublicKey) = GeneratePrivateKeyPair(keyType);
        }
        else
        {
            PrivateKey = new PrivateKey { Data = ByteString.CopyFrom(privateKey), Type = keyType };
            PublicKey = GetPublicKey(PrivateKey);
        }
    }

    public Identity(PrivateKey privateKey)
    {
        PrivateKey = privateKey;
        PublicKey = GetPublicKey(PrivateKey);
    }

    private (PrivateKey, PublicKey) GeneratePrivateKeyPair(KeyType type)
    {
        ByteString privateKeyData;
        ByteString? publicKeyData = null;
        switch (type)
        {
            case KeyType.Ed25519:
                {
                    byte[] rented = ArrayPool<byte>.Shared.Rent(Ed25519.SecretKeySize);
                    Span<byte> privateKeyBytesSpan = rented.AsSpan(0, Ed25519.SecretKeySize);
                    SecureRandom rnd = new();
                    Ed25519.GeneratePrivateKey(rnd, privateKeyBytesSpan);
                    ArrayPool<byte>.Shared.Return(rented, true);
                    privateKeyData = ByteString.CopyFrom(privateKeyBytesSpan);
                }
                break;
            case KeyType.Rsa:
                {
                    using RSA rsa = RSA.Create(1024);
                    privateKeyData = ByteString.CopyFrom(rsa.ExportRSAPrivateKey());
                }
                break;
            case KeyType.Secp256K1:
                {
                    var curve = ECNamedCurveTable.GetByName("secp256k1");
                    var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

                    var secureRandom = new SecureRandom();
                    var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

                    var generator = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator("ECDSA");
                    generator.Init(keyParams);
                    var keyPair = generator.GenerateKeyPair();
                    privateKeyData = null!;
                    Span<byte> privateKeySpan = stackalloc byte[32];
                    ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray(privateKeySpan);
                    privateKeyData = ByteString.CopyFrom(privateKeySpan);
                    publicKeyData = ByteString.CopyFrom(((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(true));
                }
                break;
            case KeyType.Ecdsa:
                {
                    using ECDsa rsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                    privateKeyData = ByteString.CopyFrom(rsa.ExportECPrivateKey());
                }
                break;
            default:
                throw new NotImplementedException($"{type} generation is not supported");
        }

        var privateKey = new PrivateKey { Type = type, Data = privateKeyData };
        return (privateKey, publicKeyData is not null ? new PublicKey { Type = type, Data = publicKeyData } : GetPublicKey(privateKey));
    }

    public Identity(PublicKey publicKey)
    {
        PublicKey = publicKey;
    }

    private static PublicKey GetPublicKey(PrivateKey privateKey)
    {
        ByteString publicKeyData;
        switch (privateKey.Type)
        {
            case KeyType.Ed25519:
                {
                    byte[] rented = ArrayPool<byte>.Shared.Rent(Ed25519.SecretKeySize);
                    Span<byte> publicKeyBytesSpan = rented.AsSpan(0, Ed25519.SecretKeySize);
                    Ed25519.GeneratePublicKey(privateKey.Data.Span, publicKeyBytesSpan);
                    publicKeyData = ByteString.CopyFrom(publicKeyBytesSpan);
                    ArrayPool<byte>.Shared.Return(rented, true);
                }
                break;

            case KeyType.Rsa:
                {
                    using RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(privateKey.Data.Span, out int bytesRead);
                    publicKeyData = ByteString.CopyFrom(rsa.ExportSubjectPublicKeyInfo());
                }
                break;

            case KeyType.Secp256K1:
                {
                    X9ECParameters curve = ECNamedCurveTable.GetByName("secp256k1");
                    Org.BouncyCastle.Math.EC.ECPoint pointQ
                        = curve.G.Multiply(new BigInteger(1, privateKey.Data.Span));
                    publicKeyData = ByteString.CopyFrom(pointQ.GetEncoded(true));
                }
                break;

            case KeyType.Ecdsa:
                {
                    using ECDsa ecdsa = ECDsa.Create();
                    ecdsa.ImportECPrivateKey(privateKey.Data.Span, out int _);
                    publicKeyData = ByteString.CopyFrom(ecdsa.ExportSubjectPublicKeyInfo());
                }
                break;
            default:
                throw new NotImplementedException($"{privateKey.Type} is not supported");
        }

        return new() { Type = privateKey.Type, Data = publicKeyData };
    }

    public bool VerifySignature(byte[] message, byte[] signature)
    {
        switch (PublicKey.Type)
        {
            case KeyType.Ed25519:
                {
                    return Ed25519.Verify(signature, 0, PublicKey.Data.ToByteArray(), 0, message, 0, message.Length);
                }
            case KeyType.Rsa:
                {
                    using RSA rsa = RSA.Create();
                    return rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            case KeyType.Secp256K1:
                {
                    X9ECParameters curve = ECNamedCurveTable.GetByName("secp256k1");
                    var signer = SignerUtilities.GetSigner("SHA-256withPLAIN-ECDSA");

                    signer.Init(false,
                        new ECPublicKeyParameters(curve.Curve.DecodePoint(PublicKey.Data.ToArray()),
                        new ECDomainParameters(curve)));
                    signer.BlockUpdate(message, 0, message.Length);
                    return signer.VerifySignature(signature);
                }
            case KeyType.Ecdsa:
                {
                    using ECDsa ecdsa = ECDsa.Create();
                    return ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256);
                }
            default:
                throw new NotImplementedException($"{PublicKey.Type} is not supported");
        }
    }

    public byte[] Sign(byte[] message)
    {
        if (PrivateKey is null)
        {
            throw new ArgumentException(nameof(PrivateKey));
        }

        switch (PublicKey.Type)
        {
            case KeyType.Ed25519:
                {
                    var sig = new byte[Ed25519.SignatureSize];
                    Ed25519.Sign(PrivateKey.Data.ToByteArray(), 0, PublicKey.Data.ToByteArray(), 0,
                        message, 0, message.Length, sig, 0);
                    return sig;
                }
            case KeyType.Ecdsa:
                {
                    var e = ECDsa.Create();
                    e.ImportECPrivateKey(PrivateKey.Data.Span, out _);
                    return e.SignData(message, HashAlgorithmName.SHA256,
                        DSASignatureFormat.Rfc3279DerSequence);
                }
            case KeyType.Rsa:
                {
                    using RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(PrivateKey.Data.Span, out _);
                    return rsa.SignData(message, 0, message.Length, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            case KeyType.Secp256K1:
                {
                    X9ECParameters curve = ECNamedCurveTable.GetByName("secp256k1");
                    var signer = SignerUtilities.GetSigner("SHA-256withPLAIN-ECDSA");

                    signer.Init(false, new ECPublicKeyParameters(curve.Curve.DecodePoint(PublicKey.Data.ToArray()), new ECDomainParameters(curve)));
                    signer.BlockUpdate(message, 0, message.Length);
                    return signer.GenerateSignature();
                }
            default:
                throw new NotImplementedException($"{PublicKey.Type} is not supported");
        }
    }

    public PeerId PeerId => new(PublicKey);
}

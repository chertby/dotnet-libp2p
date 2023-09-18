// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using Google.Protobuf;
using Nethermind.Libp2p.Core;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Nethermind.Libp2p.Protocols.Quic;
internal class CertificateHelper
{
    public static readonly Oid pubkeyExtensionOid = new("1.3.6.1.4.1.53594.1.1");
    public static readonly byte[] signaturePrefix = "libp2p-tls-handshake:"u8.ToArray();

    public static X509Certificate CertificateFromIdentity(ECDsa sessionKey, Identity identity)
    {
        byte[] signatureContent = signaturePrefix.Concat(sessionKey.ExportSubjectPublicKeyInfo()).ToArray();
        byte[] signature = identity.Sign(signatureContent);

        AsnWriter asnWrtier = new(AsnEncodingRules.DER);
        asnWrtier.PushSequence();
        asnWrtier.WriteOctetString(identity.PublicKey.ToByteArray());
        asnWrtier.WriteOctetString(signature);
        asnWrtier.PopSequence();
        byte[] pubkeyExtension = new byte[asnWrtier.GetEncodedLength()];
        asnWrtier.Encode(pubkeyExtension);

        CertificateRequest certRequest = new("", sessionKey, HashAlgorithmName.SHA256);
        certRequest.CertificateExtensions.Add(new X509Extension(pubkeyExtensionOid, pubkeyExtension, true));

        return certRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.MaxValue);
    }
}

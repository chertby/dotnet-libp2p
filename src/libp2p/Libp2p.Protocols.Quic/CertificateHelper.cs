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
    public static X509Certificate CertificateFromIdentity(ECDsa sessionKey, Identity identity)
    {
        var prefix = "libp2p-tls-handshake:"u8;
        var signatureContent = prefix.ToArray().Concat(sessionKey.ExportSubjectPublicKeyInfo()).ToArray();
        var s = identity.Sign(signatureContent);
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.PushSequence();
        w.WriteOctetString(identity.PublicKey.ToByteArray());
        w.WriteOctetString(s);
        w.PopSequence();
        var pubkeyExtension = new byte[w.GetEncodedLength()];
        w.Encode(pubkeyExtension);

        CertificateRequest certRequest = new("", sessionKey, HashAlgorithmName.SHA256);
        certRequest.CertificateExtensions.Add(new X509Extension(new Oid("1.3.6.1.4.1.53594.1.1"), pubkeyExtension, true));

        return certRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(10));
    }
}

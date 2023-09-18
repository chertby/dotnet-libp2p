// SPDX - FileCo.pyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT


using Nethermind.Libp2p.Core;
using Microsoft.Extensions.Logging;
using System.Buffers;
using System.Net.Sockets;
using MultiaddrEnum = Nethermind.Libp2p.Core.Enums.Multiaddr;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Nethermind.Libp2p.Protocols.Quic;
using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Runtime.ConstrainedExecution;

namespace Nethermind.Libp2p.Protocols;

#pragma warning disable CA1416 // Validate platform compatibility

public class QuicProtocol : IProtocol
{
    private readonly ILogger? _logger;
    private readonly ECDsa _sessionKey;

    public QuicProtocol(ILoggerFactory? loggerFactory = null)
    {
        _logger = loggerFactory?.CreateLogger<QuicProtocol>();
        _sessionKey = ECDsa.Create();
    }

    private static readonly List<SslApplicationProtocol> protocols = new()
    {
        new SslApplicationProtocol("libp2p"),
        // SslApplicationProtocol.Http3, // webtransport
    };

    public string Id => "quic";

    public async Task ListenAsync(IChannel channel, IChannelFactory? channelFactory, IPeerContext context)
    {
        if (channelFactory is null)
        {
            throw new ArgumentException($"The protocol requires {nameof(channelFactory)}");
        }

        if (!QuicListener.IsSupported)
        {
            throw new NotSupportedException("QUIC is not supported, check for presence of libmsquic and support of TLS 1.3.");
        }

        Multiaddr addr = context.LocalPeer.Address;
        MultiaddrEnum ipProtocol = addr.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6;
        IPAddress ipAddress = IPAddress.Parse(addr.At(ipProtocol)!);
        int udpPort = int.Parse(addr.At(MultiaddrEnum.Udp)!);

        IPEndPoint localEndpoint = new(ipAddress, udpPort);

        QuicServerConnectionOptions serverConnectionOptions = new()
        {
            DefaultStreamErrorCode = 0x0A, // Protocol-dependent error code.
            DefaultCloseErrorCode = 0x0B, // Protocol-dependent error code.

            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = protocols,
                RemoteCertificateValidationCallback = (_, c, _, _) => VerifyRemoteCertificate(context.RemotePeer, c),
                ServerCertificate = CertificateHelper.CertificateFromIdentity(_sessionKey, context.LocalPeer.Identity)
            },
        };

        QuicListener listener = await QuicListener.ListenAsync(new QuicListenerOptions
        {
            ListenEndPoint = localEndpoint,
            ApplicationProtocols = protocols,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverConnectionOptions)
        });

        channel.OnClose(async () =>
        {
            await listener.DisposeAsync();
        });

        while (!channel.IsClosed)
        {
            QuicConnection connection = await listener.AcceptConnectionAsync(channel.Token);
            _ = ProcessStreams(connection, context.Fork(), channelFactory, channel.Token);
        }
    }

    public async Task DialAsync(IChannel channel, IChannelFactory? channelFactory, IPeerContext context)
    {
        if (channelFactory is null)
        {
            throw new ArgumentException($"The protocol requires {nameof(channelFactory)}");
        }

        if (!QuicConnection.IsSupported)
        {
            throw new NotSupportedException("QUIC is not supported, check for presence of libmsquic and support of TLS 1.3.");
        }

        Multiaddr addr = context.LocalPeer.Address;
        MultiaddrEnum ipProtocol = addr.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6;
        IPAddress ipAddress = IPAddress.Parse(addr.At(ipProtocol)!);
        int udpPort = int.Parse(addr.At(MultiaddrEnum.Udp)!);

        IPEndPoint localEndpoint = new(ipAddress, udpPort);


        addr = context.RemotePeer.Address;
        ipProtocol = addr.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6;
        ipAddress = IPAddress.Parse(addr.At(ipProtocol)!);
        udpPort = int.Parse(addr.At(MultiaddrEnum.Udp)!);

        IPEndPoint remoteEndpoint = new(ipAddress, udpPort);

        QuicClientConnectionOptions clientConnectionOptions = new()
        {
            LocalEndPoint = localEndpoint,
            DefaultStreamErrorCode = 0, // Protocol-dependent error code.
            DefaultCloseErrorCode = 1, // Protocol-dependent error code.
            MaxInboundUnidirectionalStreams = 100,
            MaxInboundBidirectionalStreams = 100,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ApplicationProtocols = protocols,
                RemoteCertificateValidationCallback = (_, c, _, _) => VerifyRemoteCertificate(context.RemotePeer, c),
                ClientCertificates = new X509CertificateCollection { CertificateHelper.CertificateFromIdentity(_sessionKey, context.LocalPeer.Identity) },
            },
            RemoteEndPoint = remoteEndpoint,
        };

        QuicConnection connection = await QuicConnection.ConnectAsync(clientConnectionOptions);

        channel.OnClose(async () =>
        {
            await connection.CloseAsync(0);
            await connection.DisposeAsync();
        });

        _logger?.LogDebug($"Connected {connection.LocalEndPoint} --> {connection.RemoteEndPoint}");

        await ProcessStreams(connection, context, channelFactory, channel.Token);
    }

    private bool VerifyRemoteCertificate(IPeer? remotePeer, X509Certificate certificate)
    {
        if (certificate is not X509Certificate2 cert)
        {
            _logger?.LogTrace($"Certificate is not {nameof(X509Certificate2)}.");
            return false;
        }
        X509Extension[] exts = cert.Extensions.Where(e => e.Oid == CertificateHelper.pubkeyExtensionOid && e.Critical).ToArray();
        if (exts.Length is 0)
        {
            _logger?.LogTrace($"Libp2p extension was not sent by remote during QUIC handshake.");
            return true;
        }
        if (exts.Length is not 1)
        {
            _logger?.LogTrace($"There more than one libp2p extension.");
            return false;
        }
        X509Extension ext = exts.First();

        AsnReader a = new(ext.RawData, AsnEncodingRules.DER);
        AsnReader signedKey = a.ReadSequence();

        byte[] publicKey = signedKey.ReadOctetString();
        byte[] signature = signedKey.ReadOctetString();

        Core.Dto.PublicKey key = Core.Dto.PublicKey.Parser.ParseFrom(publicKey);
        Identity id = new(key);
        if (remotePeer is not null && id.PeerId.ToString() != remotePeer.Address.At(MultiaddrEnum.P2p))
        {
            _logger?.LogTrace($"PeerId does not match public key");
            return false;
        }

        ReadOnlySpan<byte> prefix = "libp2p-tls-handshake:"u8;
        IEnumerable<byte> signatureContent = prefix.ToArray().Concat(cert.PublicKey.ExportSubjectPublicKeyInfo());

        return id.VerifySignature(signatureContent.ToArray(), signature);
    }

    private async Task ProcessStreams(QuicConnection connection, IPeerContext context, IChannelFactory channelFactory, CancellationToken token)
    {
        MultiaddrEnum newIpProtocol = connection.LocalEndPoint.AddressFamily == AddressFamily.InterNetwork
           ? MultiaddrEnum.Ip4
           : MultiaddrEnum.Ip6;

        context.LocalEndpoint = Multiaddr.From(
            newIpProtocol,
            connection.LocalEndPoint.Address.ToString(),
            MultiaddrEnum.Udp,
            connection.LocalEndPoint.Port);

        context.LocalPeer.Address = context.LocalPeer.Address.Replace(
                context.LocalEndpoint.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6, newIpProtocol,
                connection.LocalEndPoint.Address.ToString())
            .Replace(
                MultiaddrEnum.Udp,
                connection.LocalEndPoint.Port.ToString());

        IPEndPoint remoteIpEndpoint = connection.RemoteEndPoint!;
        newIpProtocol = remoteIpEndpoint.AddressFamily == AddressFamily.InterNetwork
           ? MultiaddrEnum.Ip4
           : MultiaddrEnum.Ip6;

        context.RemoteEndpoint = Multiaddr.From(
            newIpProtocol,
            remoteIpEndpoint.Address.ToString(),
            MultiaddrEnum.Udp,
            remoteIpEndpoint.Port);

        context.Connected(context.RemotePeer);

        _ = Task.Run(async () =>
        {
            foreach (IChannelRequest request in context.SubDialRequests.GetConsumingEnumerable())
            {
                QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
                IPeerContext dialContext = context.Fork();
                dialContext.SpecificProtocolRequest = request;
                IChannel upChannel = channelFactory.SubDial(dialContext);
                ExchangeData(stream, upChannel, request.CompletionSource);
            }
        }, token);

        while (!token.IsCancellationRequested)
        {
            QuicStream inboundStream = await connection.AcceptInboundStreamAsync(token);
            IChannel upChannel = channelFactory.SubListen(context);
            ExchangeData(inboundStream, upChannel, null);
        }
    }

    private void ExchangeData(QuicStream stream, IChannel upChannel, TaskCompletionSource? tcs)
    {
        upChannel.OnClose(async () =>
        {
            tcs?.SetResult();
            stream.Close();
        });

        _ = Task.Run(async () =>
        {
            try
            {
                await foreach (ReadOnlySequence<byte> data in upChannel.ReadAllAsync())
                {
                    await stream.WriteAsync(data.ToArray(), upChannel.Token);
                }
            }
            catch (SocketException)
            {
                _logger?.LogInformation("Disconnected due to a socket exception");
                await upChannel.CloseAsync(false);
            }
        }, upChannel.Token);

        _ = Task.Run(async () =>
        {
            try
            {
                while (!upChannel.IsClosed)
                {
                    byte[] buf = new byte[1024];
                    int len = await stream.ReadAtLeastAsync(buf, 1, false, upChannel.Token);
                    if (len != 0)
                    {
                        await upChannel.WriteAsync(new ReadOnlySequence<byte>(buf.AsMemory()[..len]));
                    }
                }
            }
            catch (SocketException)
            {
                _logger?.LogInformation("Disconnected due to a socket exception");
                await upChannel.CloseAsync(false);
            }
        });
    }
}

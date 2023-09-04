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
using System.IO;

namespace Nethermind.Libp2p.Protocols;

public class QuicProtocol : IProtocol
{
    private readonly ILogger? _logger;

    public QuicProtocol(ILoggerFactory? loggerFactory = null)
    {
        _logger = loggerFactory?.CreateLogger<QuicProtocol>();
    }

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

        {
            new StirlingLabs.MsQuic.QuicListener(new StirlingLabs.MsQuic.QuicServerConfiguration(new StirlingLabs.MsQuic.QuicRegistration("ping"))
            {
                

            }).NewConnection += (s, o) =>
            {
                var s = o.OpenStream();
                s.Registration.
            }
        }
        Multiaddr addr = context.LocalPeer.Address;
        MultiaddrEnum ipProtocol = addr.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6;
        IPAddress ipAddress = IPAddress.Parse(addr.At(ipProtocol)!);
        int udpPort = int.Parse(addr.At(MultiaddrEnum.Udp)!);

        var localEndpoint = new IPEndPoint(ipAddress, udpPort);
        var protocols = channelFactory.SubProtocols.Select(proto => new SslApplicationProtocol(proto.Id)).ToList();

        // This represents the minimal configuration necessary to open a connection.
        var serverConnectionOptions = new QuicServerConnectionOptions
        {
            // Used to abort stream if it's not properly closed by the user.
            // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
            DefaultStreamErrorCode = 0x0A, // Protocol-dependent error code.
            
            // Used to close the connection if it's not done by the user.
            // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
            DefaultCloseErrorCode = 0x0B, // Protocol-dependent error code.

            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                // List of supported application protocols, must be the same or subset of QuicListenerOptions.ApplicationProtocols.
                ApplicationProtocols = protocols,
                // Server certificate, it can also be provided via ServerCertificateContext or ServerCertificateSelectionCallback.
                ServerCertificate = serverCertificate
            },
        };

        var listener = await QuicListener.ListenAsync(new QuicListenerOptions
        {
            // Listening endpoint, port 0 means any port.
            ListenEndPoint = localEndpoint,
            // List of all supported application protocols by this listener.
            ApplicationProtocols = protocols,
            // Callback to provide options for the incoming connections, it gets called once per each connection.
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverConnectionOptions)
        });


        // Accept and process the connections.
        while (!channel.IsClosed)
        {
            // Accept will propagate any exceptions that occurred during the connection establishment,
            // including exceptions thrown from ConnectionOptionsCallback, caused by invalid QuicServerConnectionOptions or TLS handshake failures.
            var connection = await listener.AcceptConnectionAsync();
            var str = await connection.AcceptInboundStreamAsync();
            IPeerContext clientContext = context.Fork();
            //IPEndPoint remoteIpEndpoint = (IPEndPoint)connection.RemoteEndPoint!;

            //clientContext.RemoteEndpoint = Multiaddr.From(
            //    remoteIpEndpoint.AddressFamily == AddressFamily.InterNetwork
            //        ? MultiaddrEnum.Ip4
            //        : MultiaddrEnum.Ip6, remoteIpEndpoint.Address.ToString(), MultiaddrEnum.Udp,
            //    remoteIpEndpoint.Port);
            //clientContext.LocalPeer.Address = context.LocalPeer.Address.Replace(
            //        context.LocalEndpoint.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6, newIpProtocol,
            //        remoteIpEndpoint.Address.ToString())
            //    .Replace(MultiaddrEnum.Udp, connection.LocalEndPoint.Port.ToString());
            //clientContext.RemotePeer.Address = new Multiaddr()
            //    .Append(remoteIpEndpoint.AddressFamily == AddressFamily.InterNetwork
            //        ? MultiaddrEnum.Ip4
            //        : MultiaddrEnum.Ip6, remoteIpEndpoint.Address.ToString())
            //    .Append(MultiaddrEnum.Udp, remoteIpEndpoint.Port.ToString());

            context.Connected(context.RemotePeer);

            _ = Task.Run(async () =>
            {
                foreach (IChannelRequest request in context.SubDialRequests.GetConsumingEnumerable())
                {
                    var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
                }
            });

            _ = Task.Run(async () =>
            {
                var inboundStream = await connection.AcceptInboundStreamAsync();
                IChannel chan = channelFactory.SubListen(clientContext);
                try
                {
                    while (!chan.IsClosed)
                    {
                        if (inboundStream.Position == inboundStream.Length)
                        {
                            await Task.Yield();
                        }

                        byte[] buf = new byte[connection.];
                        int len = await connection.ReceiveAsync(buf, SocketFlags.None);
                        if (len != 0)
                        {
                            await chan.WriteAsync(new ReadOnlySequence<byte>(buf.AsMemory()[..len]));
                        }
                    }
                }
                catch (SocketException)
                {
                    await chan.CloseAsync(false);
                }
            }, chan.Token);

            _ = Task.Run(async () =>
            {
                try
                {
                    await foreach (ReadOnlySequence<byte> data in chan.ReadAllAsync())
                    {
                        await connection.SendAsync(data.ToArray(), SocketFlags.None);
                    }
                }
                catch (SocketException)
                {
                    _logger?.LogInformation("Disconnected due to a socket exception");
                    await chan.CloseAsync(false);
                }
            }, chan.Token);
        }

        channel.OnClose(async () =>
        {
            await listener.DisposeAsync();
        });
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
        int tcpPort = int.Parse(addr.At(MultiaddrEnum.Udp)!);


        var localEndpoint = new IPEndPoint(ipAddress, tcpPort);
        // This represents the minimal configuration necessary to open a connection.
        var clientConnectionOptions = new QuicClientConnectionOptions
        {
            // End point of the server to connect to.
            LocalEndPoint = new IPEndPoint(ipAddress, tcpPort),

            // Used to abort stream if it's not properly closed by the user.
            // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
            DefaultStreamErrorCode = 0x0A, // Protocol-dependent error code.

            // Used to close the connection if it's not done by the user.
            // See https://www.rfc-editor.org/rfc/rfc9000#section-20.2
            DefaultCloseErrorCode = 0x0B, // Protocol-dependent error code.

            // Optionally set limits for inbound streams.
            MaxInboundUnidirectionalStreams = 10,
            MaxInboundBidirectionalStreams = 100,

            // Same options as for client side SslStream.
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                // List of supported application protocols.
                ApplicationProtocols = channelFactory.SubProtocols.Select(proto => new SslApplicationProtocol(proto.Id)).ToList()
            }
        };

        MultiaddrEnum newIpProtocol = localEndpoint.AddressFamily == AddressFamily.InterNetwork
            ? MultiaddrEnum.Ip4
            : MultiaddrEnum.Ip6;

        context.LocalEndpoint = Multiaddr.From(newIpProtocol, localEndpoint.Address.ToString(),
            MultiaddrEnum.Udp,
            localEndpoint.Port);

        context.LocalPeer.Address = context.LocalPeer.Address.Replace(
                context.LocalEndpoint.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6, newIpProtocol,
                localEndpoint.Address.ToString())
            .Replace(
                MultiaddrEnum.Udp,
                localEndpoint.Port.ToString());


        // Initialize, configure and connect to the server.
        var connection = await QuicConnection.ConnectAsync(clientConnectionOptions);

        channel.OnClose(async () =>
        {
            await connection.CloseAsync(0);
            await connection.DisposeAsync();
        });

        Console.WriteLine($"Connected {connection.LocalEndPoint} --> {connection.RemoteEndPoint}");

        _ = Task.Run(async () =>
        {
            while (!channel.IsClosed)
            {
                var incomingStream = await connection.AcceptInboundStreamAsync();
                IPeerContext clientContext = context.Fork();
                IPEndPoint remoteIpEndpoint = (IPEndPoint)client.RemoteEndPoint!;

                clientContext.RemoteEndpoint = Multiaddr.From(
                    remoteIpEndpoint.AddressFamily == AddressFamily.InterNetwork
                        ? MultiaddrEnum.Ip4
                        : MultiaddrEnum.Ip6, remoteIpEndpoint.Address.ToString(), MultiaddrEnum.Tcp,
                    remoteIpEndpoint.Port);
                clientContext.LocalPeer.Address = context.LocalPeer.Address.Replace(
                        context.LocalEndpoint.Has(MultiaddrEnum.Ip4) ? MultiaddrEnum.Ip4 : MultiaddrEnum.Ip6, newIpProtocol,
                        remoteIpEndpoint.Address.ToString())
                    .Replace(
                        MultiaddrEnum.Tcp,
                        remoteIpEndpoint.Port.ToString());
                clientContext.RemotePeer.Address = new Multiaddr()
                    .Append(remoteIpEndpoint.AddressFamily == AddressFamily.InterNetwork
                        ? MultiaddrEnum.Ip4
                        : MultiaddrEnum.Ip6, remoteIpEndpoint.Address.ToString())
                    .Append(MultiaddrEnum.Tcp, remoteIpEndpoint.Port.ToString());

                IChannel chan = channelFactory.SubListen(clientContext);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        while (!chan.IsClosed)
                        {
                            if (client.Available == 0)
                            {
                                await Task.Yield();
                            }

                            byte[] buf = new byte[client.Available];
                            int len = await client.ReceiveAsync(buf, SocketFlags.None);
                            if (len != 0)
                            {
                                await chan.WriteAsync(new ReadOnlySequence<byte>(buf.AsMemory()[..len]));
                            }
                        }
                    }
                    catch (SocketException)
                    {
                        await chan.CloseAsync(false);
                    }
                }, chan.Token);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await foreach (ReadOnlySequence<byte> data in chan.ReadAllAsync())
                        {
                            await client.SendAsync(data.ToArray(), SocketFlags.None);
                        }
                    }
                    catch (SocketException)
                    {
                        _logger?.LogInformation("Disconnected due to a socket exception");
                        await chan.CloseAsync(false);
                    }
                }, chan.Token);
            }
        });
    }
}

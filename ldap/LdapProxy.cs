using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapProxy : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly List<Task> _clients;
        private readonly CancellationTokenSource _cts;

        public LdapProxy(ushort localPort, string hostname, ushort port = 389)
        {
            _listener = TcpListener.Create(localPort);
            Hostname = hostname;
            Port = port;
            _clients = new List<Task>();
            _cts = new CancellationTokenSource();
        }

        public long MaxMessageSize { get; set; } = 1024 * 1024 * 1024;

        public ushort Port { get; }

        public string Hostname { get; }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            _listener.Start();
            using (var combined = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken))
            {
                bool running = true;
                cancellationToken.Register(() => running = false);
                var cancellationTask = Task.Delay(Timeout.Infinite, combined.Token);
                var accept = _listener.AcceptTcpClientAsync();
                while (running)
                {
                    await Task.WhenAny(_clients.Concat(new []{accept, cancellationTask}));
                    if (accept.IsCompleted)
                    {
                        TcpClient client;
                        try
                        {
                            client = await accept;
                            _clients.Add(HandleClient(client, combined.Token));
                        }
                        catch (SocketException)
                        {
                            //client may hav disconnected
                        }
                        accept = _listener.AcceptTcpClientAsync();
                    }
                    else
                    {
                        //remove finished clients
                        var finished = _clients.Where(x => x.IsCompleted).ToArray();
                        foreach (var client in finished)
                        {
                            await client;
                            _clients.Remove(client);
                        }
                    }
                }
            }
        }

        protected virtual LdapRequestMessage OnSendToServer(Guid clientId, LdapRequestMessage message)
        {
            return message;
        }

        protected virtual LdapRequestMessage OnSendToClient(Guid clientId, LdapRequestMessage message)
        {
            return message;
        }

        protected virtual void OnError(Guid clientId, LdapException exception)
        {
            return;
        }

        private async Task HandleClient(TcpClient client, CancellationToken cancellationToken)
        {
            var clientId = Guid.NewGuid();
            using(var cts = new CancellationTokenSource())
            using (var combined = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken))
            using (client)
            using (var server = new TcpClient(AddressFamily.InterNetworkV6){Client = {DualMode = true}})
            {
                await server.ConnectAsync(Hostname, Port);
                var clientSocket = client.Client;
                var serverSocket = server.Client;

                var clientPipe = new Pipe(new PipeOptions(pauseWriterThreshold: MaxMessageSize));
                var clientReader = ReadAsync(clientSocket, clientPipe.Writer, combined.Token);
                var serverWriter = WriteAsync(serverSocket, clientPipe.Reader, x => OnSendToServer(clientId, x), OnError, combined.Token);

                var serverPipe = new Pipe(new PipeOptions(pauseWriterThreshold: MaxMessageSize));
                var serverReader = ReadAsync(serverSocket, serverPipe.Writer, combined.Token);
                var clientWriter = WriteAsync(clientSocket, serverPipe.Reader, x => OnSendToClient(clientId, x), OnError, combined.Token);

                await Task.WhenAny(clientReader, serverWriter, serverReader, clientWriter);
                cts.Cancel();
            }

            void OnError(LdapException ex)
            {
                this.OnError(clientId, ex);
            }
        }

        private async Task ReadAsync(Socket socket, PipeWriter writer, CancellationToken cancellationToken)
        {
            try
            {
                while (socket.Connected)
                {
                    var buffer = writer.GetMemory(1024);
                    var read = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
                    if (read == 0)
                        break;
                    writer.Advance(read);
                    var flushed = await writer.FlushAsync(cancellationToken);
                    if (flushed.IsCompleted)
                        break;
                }
                writer.Complete();
            }
            catch (OperationCanceledException ex)
            {
                socket.Close();
                writer.Complete(ex);
            }
            catch (SocketException ex)
            {
                socket.Close();
                writer.Complete(ex);
            }
        }

        private async Task WriteAsync(Socket socket, PipeReader reader, Func<LdapRequestMessage, LdapRequestMessage> packetCallback, Action<LdapException> errorCallback, CancellationToken cancellationToken)
        {
            try
            {
                while (socket.Connected)
                {
                    var result = await reader.ReadAsync(cancellationToken);
                    var buffer = result.Buffer;

                    bool success;
                    do
                    {
                        success = false;
                        if (TryReadTagAndLength(buffer, out var tagLength))
                        {
                            if (buffer.Length >= tagLength)
                            {
                                var ldap = ReadLdapMessage(buffer.Slice(0, tagLength));
                                ldap = packetCallback(ldap);
                                await WriteLdapMessage(socket, ldap, cancellationToken);
                                buffer = buffer.Slice(tagLength);
                                success = true;
                            }
                            else if (tagLength > MaxMessageSize)
                            {
                                //maybe increase pipe size https://github.com/dotnet/corefx/issues/30689
                                throw new LdapException(ResultCode.UnwillingToPerform, "MaxMessageSize exceeded");
                            }
                        }
                    } while (success && buffer.Length > 2);
                    if (result.IsCompleted)
                        break;
                    reader.AdvanceTo(buffer.Start, buffer.End);
                }
                reader.Complete();
            }
            catch (LdapException ex)
            {
                errorCallback(ex);
                socket.Close();
                reader.Complete(ex);
            }
            catch (SocketException ex)
            {
                socket.Close();
                reader.Complete(ex);
            }
            catch (OperationCanceledException ex)
            {
                socket.Close();
                reader.Complete(ex);
            }
            catch (ObjectDisposedException ex)
            {
                if (ex.ObjectName != socket.GetType().FullName)
                    socket.Close();
                if (ex.ObjectName != reader.GetType().FullName)
                    reader.Complete(ex);
            }
            catch (Exception ex)
            {
                Debug.Fail("unexpected exception");
            }
        }

        private static bool TryReadTagAndLength(ReadOnlySequence<byte> buffer, out long length)
        {
            if (buffer.IsSingleSegment)
                return TryReadTagAndLength(buffer.First, out length);

            length = 0;
            if (!AsnReader.TryPeekTag(buffer.First.Span, out _, out int tagBytes))
                return false;
            buffer = buffer.Slice(tagBytes);
            if (!AsnReader.TryReadLength(buffer.First.Span, AsnEncodingRules.BER, out var asnLength, out var lengthBytes))
                return false;
            if (!asnLength.HasValue)
                return false;
            length = asnLength.Value;
            length += lengthBytes;
            length+= tagBytes;
            return true;
        }


        private static bool TryReadTagAndLength(ReadOnlyMemory<byte> buffer, out long length)
        {
            length = 0;
            if (!AsnReader.TryPeekTag(buffer.Span, out _, out int tagBytes))
                return false;
            if (!AsnReader.TryReadLength(buffer.Span.Slice(tagBytes), AsnEncodingRules.BER, out var asnLength, out var lengthBytes))
                return false;
            if (!asnLength.HasValue)
                return false;
            length = asnLength.Value;
            length += lengthBytes;
            length+= tagBytes;
            return true;
        }

        private static async Task WriteLdapMessage(Socket socket, LdapRequestMessage ldap, CancellationToken cancellationToken)
        {
            var asn = ldap.GetAsn();
            using (var asnwriter = new AsnWriter(AsnEncodingRules.BER))
            {
                asn.Encode(asnwriter);
                var bytes = asnwriter.Encode();
                await socket.SendAsync(bytes, SocketFlags.None, cancellationToken);
            }
        }

        private static LdapRequestMessage ReadLdapMessage(ReadOnlySequence<byte> buffer)
        {
            if (buffer.IsSingleSegment)
                return ReadLdapMessage(buffer.First);
            return ReadLdapMessage(buffer.ToArray());
        }

        private static LdapRequestMessage ReadLdapMessage(ReadOnlyMemory<byte> buffer)
        {
            var message = Asn1Serializer.Deserialize(buffer);
            return LdapRequestMessage.Create(message);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _listener.Stop();
                _cts.Cancel();
                _cts.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
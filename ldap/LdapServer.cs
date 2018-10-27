using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts;
        private readonly List<Task> _clients;

        protected LdapServer(ushort port)
        {
            _listener = TcpListener.Create(port);
            _clients = new List<Task>();
            _cts = new CancellationTokenSource();
        }
        
        public long MaxMessageSize { get; set; } = 1024 * 1024 * 1024;

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
        
        protected virtual void OnError(LdapClientConnection connection, LdapException exception)
        {
            return;
        }

        protected virtual Task<LdapRequestMessage> OnBindAsync(LdapBindRequest request, LdapClientConnection connection)
        {
            return Task.FromResult(request.Response(ResultCode.Other, "Not Implemented"));
        }

        private async Task OnRequestAsync(LdapRequestMessage message, LdapClientConnection connection)
        {
            if (!await connection.TryAddPendingAsync(message))
                return;
            try
            {

                if (message is LdapAbandonRequest abandon)
                {
                    connection.AbandonRequest(abandon.MessageId);
                }
                if (message is LdapBindRequest bind)
                {
                    try
                    {
                        await connection.BeginBindAsync();
                        var response = await BindRequestAsync(bind, connection);
                        await WriteAsync(response, connection);
                    }
                    finally
                    {
                        connection.FinishBind();
                    }
                }
                else if (message is LdapUnbindRequest)
                {
                    UnbindRequest(connection);
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
            finally
            {
                connection.RemovePending(message);
            }
        }

        private Task<LdapRequestMessage> BindRequestAsync(LdapBindRequest request, LdapClientConnection connection)
        {
            if (request.Version != 3)
            {
                return Task.FromResult(request.Response(ResultCode.ProtocolError, "only version 3 is supported"));
            }
            return OnBindAsync(request, connection);
        }

        private void UnbindRequest(LdapClientConnection connection)
        {
            connection.CloseConnection();
        }

        private async Task HandleClient(TcpClient client, CancellationToken cancellationToken)
        {
            using(var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            using (client)
            {
                var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: MaxMessageSize));
                using (var connection = new LdapClientConnection(client, pipe, cts))
                {
                    var writing = FillPipeAsync(connection);
                    var reading = ReadPipeAsync(connection);
                    await Task.WhenAny(reading, writing);
                    cts.Cancel();
                }
            }
        }

        private async Task FillPipeAsync(LdapClientConnection connection)
        {
            try
            {
                while (connection.Socket.Connected)
                {
                    var buffer = connection.Writer.GetMemory(1024);
                    var read = await connection.Socket.ReceiveAsync(buffer, SocketFlags.None, connection.CancellationToken);
                    if (read == 0)
                        break;
                    connection.Writer.Advance(read);
                    var flushed = await connection.Writer.FlushAsync(connection.CancellationToken);
                    if (flushed.IsCompleted)
                        break;
                }
                connection.Writer.Complete();
            }
            catch (OperationCanceledException ex)
            {
                connection.Socket.Close();
                connection.Writer.Complete(ex);
            }
            catch (SocketException ex)
            {
                connection.Socket?.Close();
                connection.Writer.Complete(ex);
            }
        }

        private async Task ReadPipeAsync(LdapClientConnection connection)
        {
            try
            {
                var tasks = new List<Task>();
                while (true)
                {
                    var read = connection.Reader.ReadAsync(connection.CancellationToken);
                    ReadResult result;
                    if (!read.IsCompleted)
                    {
                        var readTask = read.AsTask();
                        tasks.Add(readTask);
                        while (!read.IsCompleted)
                        {
                            await Task.WhenAny(tasks);
                            if (!read.IsCompleted)
                            {
                                //remove finished messages
                                var finished = tasks.Where(x => x.IsCompleted).ToList();
                                foreach (var task in finished)
                                {
                                    await task;
                                    tasks.Remove(task);
                                }
                            }
                        }
                        tasks.Remove(readTask);
                        result = await readTask;
                    }
                    else
                    {
                        result = await read;
                    }
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
                                var process = OnRequestAsync(ldap, connection);
                                tasks.Add(process);
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
                    connection.Reader.AdvanceTo(buffer.Start, buffer.End);
                }
                connection.Reader.Complete();
            }
            catch (LdapException ex)
            {
                OnError(connection, ex);
                connection.Reader.Complete(ex);
            }
            catch (SocketException ex)
            {
                connection.Reader.Complete(ex);
            }
            catch (OperationCanceledException ex)
            {
                connection.Reader.Complete(ex);
            }
            catch (ObjectDisposedException ex)
            {
                if (ex.ObjectName != connection.Reader.GetType().FullName)
                    connection.Reader.Complete(ex);
            }
        }

        private async Task WriteAsync(LdapRequestMessage message, LdapClientConnection connection)
        {
            var asn = message.GetAsn();
            using (var asnwriter = new AsnWriter(AsnEncodingRules.BER))
            {
                asn.Encode(asnwriter);
                var bytes = asnwriter.Encode();
                await connection.WriteAsync(bytes);
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
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
using zivillian.ldap.Asn1;
using zivillian.ldap.Attributes;
using zivillian.ldap.ObjectClasses;

namespace zivillian.ldap
{
    public abstract class LdapServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts;
        private readonly List<Task> _clients;
        private readonly TopObjectClass _rootDse;
        private readonly HashSet<string> _controls;
        private SslServerAuthenticationOptions _sslOptions;
        private TcpListener _sslListener;

        protected LdapServer(ushort port, TopObjectClass rootDse)
            : this(TcpListener.Create(port), rootDse)
        {
        }

        protected LdapServer(IPEndPoint endPoint, TopObjectClass rootDse)
            : this(new TcpListener(endPoint), rootDse)
        {
        }

        private LdapServer(TcpListener listener, TopObjectClass rootDse)
        {
            _listener = listener;
            _clients = new List<Task>();
            _cts = new CancellationTokenSource();
            _rootDse = rootDse;
            _controls = _rootDse.GetAttributes()
                .OfType<SupportedControlAttribute>()
                .Select(x => x.Oid)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        
        public long MaxMessageSize { get; set; } = 1024 * 1024 * 1024;

        public void UseSsl(SslServerAuthenticationOptions sslOptions)
        {
            UseSsl(636, sslOptions);
        }

        public void UseSsl(ushort port, SslServerAuthenticationOptions sslOptions)
        {
            _sslOptions = sslOptions;
            var endPoint = (IPEndPoint) _listener.LocalEndpoint;
            _sslListener = new TcpListener(endPoint.Address, port);
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            _listener.Start();
            using (var combined = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken))
            {
                bool running = true;
                cancellationToken.Register(() => running = false);
                var cancellationTask = Task.Delay(Timeout.Infinite, combined.Token);
                var accept = _listener.AcceptTcpClientAsync();
                Task<TcpClient> sslAccept;
                if (_sslOptions != null)
                {
                    _sslListener.Start();
                    sslAccept = _sslListener.AcceptTcpClientAsync();
                }
                else
                {
                    sslAccept = Task.Delay(-1, combined.Token).ContinueWith(x => (TcpClient) null, combined.Token,
                        TaskContinuationOptions.LongRunning, TaskScheduler.Current);
                }
                while (running)
                {
                    await Task.WhenAny(_clients.Concat(new []{accept, sslAccept, cancellationTask})).ConfigureAwait(false);
                    if (accept.IsCompleted || sslAccept.IsCompleted)
                    {
                        try
                        {
                            TcpClient client;
                            bool ssl;
                            if (accept.IsCompleted)
                            {
                                client = await accept.ConfigureAwait(false);
                                accept = _listener.AcceptTcpClientAsync();
                                ssl = false;
                            }
                            else
                            {
                                client = await sslAccept.ConfigureAwait(false);
                                sslAccept = _sslListener.AcceptTcpClientAsync();
                                ssl = true;
                            }
                            _clients.Add(HandleClient(client, ssl, combined.Token));
                        }
                        catch (SocketException)
                        {
                            //client may have disconnected
                        }
                    }
                    else
                    {
                        //remove finished clients
                        var finished = _clients.Where(x => x.IsCompleted).ToArray();
                        foreach (var client in finished)
                        {
                            await client.ConfigureAwait(false);
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

        protected virtual void OnClientDisconnected(Guid connectionId)
        {

        }

        protected virtual Task<LdapBindResponse> OnBindAsync(LdapBindRequest request, LdapClientConnection connection)
        {
            return Task.FromResult(request.Response(ResultCode.Other, "Not Implemented"));
        }

        protected virtual Task<IEnumerable<LdapRequestMessage>> OnSearchAsync(LdapSearchRequest request, LdapClientConnection connection, CancellationToken cancellationToken)
        {
            return Task.FromResult(Enumerable.Empty<LdapRequestMessage>());
        }

        protected virtual Task<IList<LdapAttribute>> OnGetRootDSEAsync(IList<LdapAttribute> attributes, LdapClientConnection connection, CancellationToken cancellationToken)
        {
            return Task.FromResult(attributes);
        }

        private async Task OnRequestAsync(LdapRequestMessage message, LdapClientConnection connection)
        {
            if (!await connection.TryAddPendingAsync(message).ConfigureAwait(false))
                return;
            try
            {

                if (message is LdapAbandonRequest abandon)
                {
                    if (CriticalControlsSupported(abandon.Controls))
                        connection.AbandonRequest(abandon.MessageId);
                }
                else if (message is LdapBindRequest bind)
                {
                    try
                    {
                        await connection.BeginBindAsync().ConfigureAwait(false);
                        var response = await BindRequestAsync(bind, connection).ConfigureAwait(false);
                        await WriteAsync(response, connection).ConfigureAwait(false);
                    }
                    catch(Exception ex)
                    {
                        await WriteAsync(bind.Response(ResultCode.Other, ex.Message), connection).ConfigureAwait(false);
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
                else if (message is LdapSearchRequest search)
                {
                    await SearchRequestAsync(search, connection).ConfigureAwait(false);
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

        private Task<LdapBindResponse> BindRequestAsync(LdapBindRequest request, LdapClientConnection connection)
        {
            if (request.Version != 3)
            {
                return Task.FromResult(request.Response(ResultCode.ProtocolError, "only version 3 is supported"));
            }
            if (!CriticalControlsSupported(request.Controls))
            {
                return Task.FromResult(request.Response(ResultCode.UnavailableCriticalExtension, String.Empty));
            }
            if (request.Simple.HasValue && request.Simple.Value.Length == 0 && request.Name.RDNs.Count > 0)
            {
                //https://tools.ietf.org/html/rfc4513#section-5.1.2
                return Task.FromResult(request.Response(ResultCode.UnwillingToPerform, "Unauthenticated Bind"));
            }
            return OnBindAsync(request, connection);
        }

        private static void UnbindRequest(LdapClientConnection connection)
        {
            connection.CloseConnection();
        }

        private async Task SearchRequestAsync(LdapSearchRequest request, LdapClientConnection connection)
        {
            if (request.TimeLimit != TimeSpan.Zero)
            {
                using(var cts = new CancellationTokenSource(request.TimeLimit))
                using (var combined = CancellationTokenSource.CreateLinkedTokenSource(connection.CancellationToken, cts.Token))
                {
                    await SearchRequestAsync(request, connection, combined.Token).ConfigureAwait(false);
                }
            }
            else
            {
                await SearchRequestAsync(request, connection, connection.CancellationToken).ConfigureAwait(false);
            }
        }

        private async Task SearchRequestAsync(LdapSearchRequest request, LdapClientConnection connection, CancellationToken cancellationToken)
        {
            try
            {
                if (request.BaseObject.RDNs.Count == 0 &&
                    request.Scope == SearchScope.BaseObject &&
                    request.Filter is LdapPresentFilter filter &&
                    (filter.Attribute.Oid.Equals("objectClass", StringComparison.OrdinalIgnoreCase) || filter.Attribute.Oid == "2.5.4.0"))
                {
                    IList<LdapAttribute> attributes = _rootDse.GetAttributes(request.Attributes, request.TypesOnly).ToList();
                    attributes = await OnGetRootDSEAsync(attributes, connection, cancellationToken).ConfigureAwait(false);
                    var entry = request.Result(LdapDistinguishedName.Empty, attributes.ToArray(), Array.Empty<LdapControl>());
                    await WriteAsync(entry, connection).ConfigureAwait(false);
                    await WriteAsync(request.Done(), connection).ConfigureAwait(false);
                }
                else
                {
                    var results = await OnSearchAsync(request, connection, cancellationToken).ConfigureAwait(false);
                    bool done = false;
                    foreach (var response in results)
                    {
                        await WriteAsync(response, connection).ConfigureAwait(false);
                        if (response is LdapSearchResultDone)
                        {
                            done = true;
                            break;
                        }
                    }
                    if (!done)
                    {
                        await WriteAsync(request.Done(), connection).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                var done = request.Done(ResultCode.TimeLimitExceeded);
                await WriteAsync(done, connection).ConfigureAwait(false);
            }
        }

        private async Task HandleClient(TcpClient client, bool useSsl, CancellationToken cancellationToken)
        {
            using(var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            using (client)
            {
                var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: MaxMessageSize));
                Stream stream = client.GetStream();
                if (useSsl)
                {
                    var ssl = new SslStream(stream);
                    await ssl.AuthenticateAsServerAsync(_sslOptions, cancellationToken).ConfigureAwait(false);
                    stream = ssl;
                }
                using (var connection = new LdapClientConnection(client, stream, pipe, cts))
                {
                    try
                    {
                        var writing = FillPipeAsync(connection);
                        var reading = ReadPipeAsync(connection);
                        await Task.WhenAny(reading, writing).ConfigureAwait(false);
                    }
                    finally
                    {
                        cts.Cancel();
                        OnClientDisconnected(connection.Id);
                    }
                }
            }
        }

        private static async Task FillPipeAsync(LdapClientConnection connection)
        {
            try
            {
                while (connection.IsConnected)
                {
                    var buffer = connection.Writer.GetMemory(1024);
                    var read = await connection.Stream.ReadAsync(buffer, connection.CancellationToken);
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
                connection.Stream.Close();
                connection.Writer.Complete(ex);
            }
            catch (SocketException ex)
            {
                connection.Stream?.Close();
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
                            await Task.WhenAny(tasks).ConfigureAwait(false);
                            if (!read.IsCompleted)
                            {
                                //remove finished messages
                                var finished = tasks.Where(x => x.IsCompleted).ToList();
                                foreach (var task in finished)
                                {
                                    await task.ConfigureAwait(false);
                                    tasks.Remove(task);
                                }
                            }
                        }
                        tasks.Remove(readTask);
                        result = await readTask.ConfigureAwait(false);
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

        private static async Task WriteAsync(LdapRequestMessage message, LdapClientConnection connection)
        {
            var asn = message.GetAsn();
            using (var asnwriter = new AsnWriter(AsnEncodingRules.BER))
            {
                asn.Encode(asnwriter);
                var bytes = asnwriter.Encode();
                await connection.WriteAsync(bytes).ConfigureAwait(false);
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

        private bool CriticalControlsSupported(IEnumerable<LdapControl> controls)
        {
            foreach (var control in controls)
            {
                if (control.Criticality)
                {
                    if (!_controls.Contains(control.Oid))
                        return false;
                }
            }
            return true;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _listener.Stop();
                _sslListener?.Stop();
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
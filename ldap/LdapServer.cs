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
using System.Text;
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
        private readonly IPAddress _localAddress;

        protected LdapServer(ushort port, TopObjectClass rootDse)
            : this(TcpListener.Create(port), rootDse)
        {
        }

        protected LdapServer(IPEndPoint endPoint, TopObjectClass rootDse)
            : this(new TcpListener(endPoint), rootDse)
        {
            _localAddress = endPoint.Address;
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
            if (_localAddress == null)
            {
                _sslListener = TcpListener.Create(port);
            }
            else
            {
                _sslListener = new TcpListener(_localAddress, port);
            }
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
                        catch (IOException)
                        {
                            //client may have disconnected during ssl handshake
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

        protected virtual Task<ResultCode> OnBindAsync(LdapDistinguishedName bindDN, ReadOnlyMemory<byte> password, LdapClientConnection connection)
        {
            return Task.FromResult(ResultCode.Other);
        }

        protected virtual Task<ResultCode> OnSaslBindAsync(LdapDistinguishedName bindDN, string username, ReadOnlyMemory<byte> password, LdapClientConnection connection)
        {
            return Task.FromResult(ResultCode.Other);
        }

        protected virtual Task<IEnumerable<LdapRequestMessage>> OnSearchAsync(LdapSearchRequest request, LdapClientConnection connection, CancellationToken cancellationToken)
        {
            return Task.FromResult(Enumerable.Empty<LdapRequestMessage>());
        }

        protected virtual Task<ICollection<LdapAttribute>> OnGetRootDSEAsync(ICollection<LdapAttribute> attributes, LdapClientConnection connection, CancellationToken cancellationToken)
        {
            return Task.FromResult(attributes);
        }

        protected virtual Task<LdapExtendedResponse> OnExtendedAsync(LdapExtendedRequest request, LdapClientConnection connection)
        {
            return Task.FromResult(request.NotSupported());
        }

        private async Task OnRequestAsync(LdapRequestMessage message, LdapClientConnection connection)
        {
            if (!await connection.TryAddPendingAsync(message).ConfigureAwait(false))
                return;
            try
            {

                if (message is LdapAbandonRequest abandon)
                {
                    connection.ContinueRead();
                    if (CriticalControlsSupported(abandon.Controls))
                        connection.AbandonRequest(abandon.MessageId);
                }
                else if (message is LdapBindRequest bind)
                {
                    connection.ContinueRead();
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
                    connection.ContinueRead();
                    UnbindRequest(connection);
                }
                else if (message is LdapSearchRequest search)
                {
                    connection.ContinueRead();
                    await SearchRequestAsync(search, connection).ConfigureAwait(false);
                }
                else if (message is LdapExtendedRequest extended)
                {
                    await ExtendedRequestAsync(extended, connection).ConfigureAwait(false);
                }
                else
                {
                    connection.ContinueRead();
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
            if (request.SaslMechanism != null && request.SaslMechanism.Length == 0)
            {
                return Task.FromResult(request.Response(ResultCode.AuthMethodNotSupported, "SASL aborted"));
            }
            return OnBindAsync(request, connection);
        }

        private async Task<LdapBindResponse> OnBindAsync(LdapBindRequest request, LdapClientConnection connection)
        {
            ResultCode result = ResultCode.AuthMethodNotSupported;
            if (request.Simple != null)
            {
                result = await OnBindAsync(request.Name, request.Simple.Value, connection).ConfigureAwait(false);
            }
            else if (request.SaslMechanism == SupportedSASLMechanismsAttribute.Anonymous)
            {
                var credentials = request.SaslCredentials.GetValueOrDefault(ReadOnlyMemory<byte>.Empty);
                result = await OnSaslBindAsync(request.Name, String.Empty, credentials, connection).ConfigureAwait(false);
            }
            else if (request.SaslMechanism == SupportedSASLMechanismsAttribute.Plain)
            {
                if (request.SaslCredentials == null)
                {
                    result = ResultCode.InappropriateAuthentication;
                }
                else
                {
                    var credentials = request.SaslCredentials.Value;
                    var first = credentials.Span.IndexOf((byte) 0);
                    var last = credentials.Span.LastIndexOf((byte) 0);
                    if (first == last)
                    {
                        result = ResultCode.InappropriateAuthentication;
                    }
                    else
                    {
                        first++;
                        var user = Encoding.UTF8.GetString(credentials.Slice(first, last - first).Span);
                        var password = credentials.Slice(last + 1);
                        result = await OnSaslBindAsync(request.Name, user, password, connection).ConfigureAwait(false);
                    }
                }
            }
            switch (result)
            {
                case ResultCode.Other:
                    return request.Response(result, "Not implemented");
                case ResultCode.Success:
                    return request.Response();
                default:
                    return request.Response(result, String.Empty);
            }
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
                    ICollection<LdapAttribute> attributes = _rootDse.GetAttributes(request.Attributes, request.TypesOnly).ToList();
                    if (_sslOptions != null && request.Attributes.Where(x=>x.Selector != null).Any(x=>x.Selector.Oid == SupportedExtensionAttribute.OidValue || x.Selector.Oid == SupportedExtensionAttribute.ShortName))
                    {
                        var attribute = attributes.OfType<SupportedExtensionAttribute>().FirstOrDefault();
                        if (attribute == null)
                        {
                            attribute = new SupportedExtensionAttribute
                            {
                                Entries = {LdapExtendedRequest.StartTLS}
                            };
                            attributes.Add(attribute);
                        }
                        else
                        {
                            attribute.Entries.Add(LdapExtendedRequest.StartTLS);
                        }
                    }
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

        private Task ExtendedRequestAsync(LdapExtendedRequest request, LdapClientConnection connection)
        {
            if (request.Name == LdapExtendedRequest.StartTLS)
            {
                return StartTLS(request, connection);
            }
            else
            {
                connection.ContinueRead();
                return OnExtendedAsync(request, connection).ContinueWith(x =>
                {
                    var response = x.Result;
                    return WriteAsync(response, connection).ConfigureAwait(false);
                }, connection.CancellationToken, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Current);
            }
        }

        private async Task StartTLS(LdapExtendedRequest request, LdapClientConnection connection)
        {
            if (_sslOptions == null || !await connection.BeginStartSSL().ConfigureAwait(false))
            {
                connection.ContinueRead();
                await WriteAsync(request.NotSupported(), connection).ConfigureAwait(false);
            }
            try
            {
                await WriteAsync(request.StartTlsResponse(), connection).ConfigureAwait(false);
                await connection.StartSSLAsync(_sslOptions).ConfigureAwait(false);
                connection.ContinueRead();
            }
            finally
            {
                connection.FinishStartSSL();
            }
        }

        private async Task HandleClient(TcpClient client, bool useSsl, CancellationToken cancellationToken)
        {
            using(var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            using (client)
            {
                var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: MaxMessageSize));
                using (var connection = new LdapClientConnection(client, pipe, cts))
                {
                    if (useSsl)
                    {
                        await connection.UseSSLAsync(_sslOptions).ConfigureAwait(false);
                    }
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
                    var read = await connection.ReadAsync(buffer).ConfigureAwait(false);
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
                connection.Writer.Complete(ex);
            }
            catch (SocketException ex)
            {
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
                            else
                            {
                                connection.ContinueRead();
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
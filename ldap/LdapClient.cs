using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapClient:IDisposable
    {
        private readonly TcpClient _client;
        private int _sizeLimit;
        private int _messageId;
        private TimeSpan _timeLimit;
        private Task _reader;
        private Task _dispatcher;
        private bool _closed;
        private Pipe _pipe;
        private readonly SemaphoreSlim _writeLock;
        private readonly ConcurrentDictionary<int, MessageState> _receiveQueue = new ConcurrentDictionary<int, MessageState>();
        private readonly CancellationTokenSource _closeTokenSource;

        public LdapClient(string hostname, ushort port = 389)
        {
            _client = new TcpClient(AddressFamily.InterNetworkV6)
            {
                Client = {DualMode = true}
            };
            Hostname = hostname;
            Port = port;
            ServerControls = new List<LdapControl>();
            _writeLock = new SemaphoreSlim(1, 1);
            _closeTokenSource = new CancellationTokenSource();
        }

        public long MaxMessageSize { get; set; } = 1024 * 1024 * 1024;

        public DerefAliases Deref { get; set; }

        public int SizeLimit
        {
            get => _sizeLimit;
            set
            {
                if (_sizeLimit < 0)
                    throw new ArgumentOutOfRangeException(nameof(value));
                _sizeLimit = value;
            }
        }

        public TimeSpan TimeLimit
        {
            get => _timeLimit;
            set
            {
                if (_timeLimit < TimeSpan.Zero)
                    throw new ArgumentOutOfRangeException(nameof(value));
                _timeLimit = value;
            }
        }

        public bool Referrals { get; set; } = true;
        
        public string Hostname { get; }

        public ushort Port { get; }

        public List<LdapControl> ServerControls { get; }

        public Task SimpleBindAsync(string dn, string password, CancellationToken cancellationToken)
        {
            return SimpleBindAsync(dn, password, ServerControls.ToArray(), cancellationToken);
        }

        public async Task SimpleBindAsync(string dn, string password, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            var request = new LdapBindRequest(NextMessageId(), dn, password, serverControls);
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            var bindResponse = (LdapBindResponse) response;
            if (bindResponse.ResultCode != ResultCode.Success)
                throw new LdapException(bindResponse);
        }

        public Task SaslBindAsync(string dn, string mechanism, ReadOnlyMemory<byte> credentials, CancellationToken cancellationToken)
        {
            return SaslBindAsync(dn, mechanism, credentials, ServerControls.ToArray(), cancellationToken);
        }

        public async Task<LdapBindResponse> SaslBindAsync(string dn, string mechanism, ReadOnlyMemory<byte> credentials, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            var request = new LdapBindRequest(NextMessageId(), dn, mechanism, credentials, serverControls);
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            var bindResponse = (LdapBindResponse) response;
            if (bindResponse.ResultCode != ResultCode.Success)
                throw new LdapException(bindResponse);
            return bindResponse;
        }

        public Task UnbindAsync(CancellationToken cancellationToken)
        {
            return UnbindAsync(ServerControls.ToArray(), cancellationToken);
        }

        public async Task UnbindAsync(LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            var request = new LdapUnbindRequest(NextMessageId(), serverControls);
            await SendWithoutResponseAsync(request, cancellationToken).ConfigureAwait(false);
            Dispose(true);
        }

        public Task<LdapSearchResult> SearchAsync(string baseDn, SearchScope scope, string filter, CancellationToken cancellationToken)
        {
            return SearchAsync(baseDn, scope, filter, null, cancellationToken);
        }

        public Task<LdapSearchResult> SearchAsync(string baseDn, SearchScope scope, string filter, string[] attributes, CancellationToken cancellationToken)
        {
            return SearchAsync(baseDn, scope, filter, attributes, false, cancellationToken);
        }

        public Task<LdapSearchResult> SearchAsync(string baseDn, SearchScope scope, string filter, string[] attributes, bool attributeTypesOnly, CancellationToken cancellationToken)
        {
            return SearchInternalAsync(baseDn, scope, filter, attributes, attributeTypesOnly, TimeSpan.Zero, 0, null, cancellationToken);
        }

        public async Task<LdapSearchResult> SearchAsync(string baseDn, SearchScope scope, string filter, string[] attributes, bool attributeTypesOnly, TimeSpan timeout, CancellationToken cancellationToken)
        {
            using (var timeoutTokenSource = new CancellationTokenSource(timeout))
            using (var combined = CancellationTokenSource.CreateLinkedTokenSource(timeoutTokenSource.Token, cancellationToken))
            {
                return await SearchInternalAsync(baseDn, scope, filter, attributes, attributeTypesOnly, TimeSpan.Zero, 0, null, combined.Token).ConfigureAwait(false);
            }
        }

        public async Task<LdapSearchResult> SearchAsync(string baseDn, SearchScope scope, string filter, string[] attributes, bool attributeTypesOnly, TimeSpan timeout, int sizeLimit, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            using (var timeoutTokenSource = new CancellationTokenSource(timeout))
            using (var combined = CancellationTokenSource.CreateLinkedTokenSource(timeoutTokenSource.Token, cancellationToken))
            {
                return await SearchInternalAsync(baseDn, scope, filter, attributes, attributeTypesOnly, timeout, sizeLimit, serverControls, combined.Token).ConfigureAwait(false);
            }
        }

        public Task<bool> CompareAsync(string dn, string attribute, string value, CancellationToken cancellationToken)
        {
            return CompareAsync(dn, attribute, value, ServerControls.ToArray(), cancellationToken);
        }

        public Task<bool> CompareAsync(string dn, string attribute, ReadOnlyMemory<byte> value, CancellationToken cancellationToken)
        {
            return CompareAsync(dn, attribute, value, ServerControls.ToArray(), cancellationToken);
        }

        public Task<bool> CompareAsync(string dn, string attribute, string value, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            var assertion = new LdapAttributeAssertion(attribute, value);
            return CompareAsync(dn, assertion, serverControls, cancellationToken);
        }

        public Task<bool> CompareAsync(string dn, string attribute, ReadOnlyMemory<byte> value, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            var assertion = new LdapAttributeAssertion(attribute, value);
            return CompareAsync(dn, assertion, serverControls, cancellationToken);
        }

        private async Task<bool> CompareAsync(string dn, LdapAttributeAssertion assertion, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            var request = new LdapCompareRequest(NextMessageId(), dn, assertion, serverControls);
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            var compareResponse = (LdapCompareResponse) response;
            switch (compareResponse.ResultCode)
            {
                case ResultCode.CompareTrue:
                    return true;
                case ResultCode.CompareFalse:
                    return false;
                default:
                    throw new LdapException(compareResponse.ResultCode, compareResponse.DiagnosticMessage ?? "unexpected compare response code");
            }
        }

        private async Task<LdapSearchResult> SearchInternalAsync(string baseDn, SearchScope scope, string filter, string[] attributes, bool attributeTypesOnly, TimeSpan timeout, int sizeLimit, LdapControl[] serverControls, CancellationToken cancellationToken)
        {
            if (filter is null)
                filter = "(objectclass=*)";

            var request = new LdapSearchRequest(NextMessageId(), baseDn, scope, filter, attributes, attributeTypesOnly, timeout, sizeLimit, serverControls);
            var state = new MessageState(request.Id, cancellationToken);
            _receiveQueue.AddOrUpdate(state.MessageId, state, (i, o) => throw new InvalidOperationException());
            var result = new LdapSearchResult();
            try
            {
                await SendWithoutResponseAsync(request, cancellationToken).ConfigureAwait(false);
                var message = await state.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                while (result.Add(message))
                {
                    message = await state.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                }
                var done = (LdapSearchResultDone) message;
                switch (done.ResultCode)
                {
                    case ResultCode.Success:
                        break;
                    case ResultCode.Referral:
                        throw new NotImplementedException("referral");
                    default:
                        throw new LdapException(done.ResultCode);
                }
            }
            catch(OperationCanceledException)
            {
                await AbandonAsync(request.Id, CancellationToken.None).ConfigureAwait(false);
                throw;
            }
            state.Responses.Complete();
            if (!_receiveQueue.TryRemove(state.MessageId, out _))
                throw new InvalidOperationException();
            return result;
        }

        private Task AbandonAsync(int messageId, CancellationToken cancellationToken)
        {
            return SendWithoutResponseAsync(new LdapAbandonRequest(messageId, NextMessageId(), ServerControls.ToArray()), cancellationToken);
        }

        private async Task SendWithoutResponseAsync(LdapRequestMessage request, CancellationToken cancellationToken)
        {
            await ConnectAsync().ConfigureAwait(false);

            var asn = request.GetAsn();
            var stream = _client.GetStream();
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ReadOnlyMemory<byte> bytes;
                using (var writer = new AsnWriter(AsnEncodingRules.BER))
                {
                    asn.Encode(writer);
                    bytes = writer.Encode();
                }
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        private async Task<LdapRequestMessage> SendAsync(LdapRequestMessage request, CancellationToken cancellationToken)
        {
            var state = new MessageState(request.Id, cancellationToken);
            _receiveQueue.AddOrUpdate(state.MessageId, state, (i, o) => throw new InvalidOperationException());
            await SendWithoutResponseAsync(request, cancellationToken).ConfigureAwait(false);
            var result = await state.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            state.Responses.Complete();
            if (!_receiveQueue.TryRemove(state.MessageId, out _))
                throw new InvalidOperationException();
            return result;
        }

        private async Task ConnectAsync()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);
            if (_client.Connected) return;

            if (Hostname.Contains(' ', StringComparison.Ordinal))
                throw new NotImplementedException("hostname parsing");

            await _client.ConnectAsync(Hostname, Port).ConfigureAwait(false);
            _pipe = new Pipe(new PipeOptions(pauseWriterThreshold:MaxMessageSize));
            _reader = ReadAsync(_closeTokenSource.Token);
            _dispatcher = DispatchAsync(_closeTokenSource.Token);
        }

        private async Task DispatchAsync(CancellationToken cancellationToken)
        {
            var reader = _pipe.Reader;
            try
            {
                using (var socket = _client.Client)
                while (!_closed && socket.Connected)
                {
                    var result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                    var buffer = result.Buffer;

                    bool success;
                    do
                    {
                        success = false;
                        if (LdapProxy.TryReadTagAndLength(buffer, out var tagLength))
                        {
                            if (buffer.Length >= tagLength)
                            {
                                var ldap = ReadLdapMessage(buffer.Slice(0, tagLength));
                                OnMessageReceived(ldap);
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
                reader.Complete(ex);
            }
            catch (SocketException ex)
            {
                reader.Complete(ex);
            }
            catch (OperationCanceledException ex)
            {
                reader.Complete(ex);
            }
            catch (ObjectDisposedException ex)
            {
                if (ex.ObjectName != reader.GetType().FullName)
                    reader.Complete(ex);
            }
        }

        private static Asn1LdapMessage ReadLdapMessage(ReadOnlySequence<byte> buffer)
        {
            if (buffer.IsSingleSegment)
                return ReadLdapMessage(buffer.First);
            return ReadLdapMessage(buffer.ToArray());
        }

        private static Asn1LdapMessage ReadLdapMessage(ReadOnlyMemory<byte> buffer)
        {
            return Asn1Serializer.Deserialize(buffer);
        }

        private void OnMessageReceived(Asn1LdapMessage message)
        {
            var ldapMessage = LdapRequestMessage.Create(message);
            if (_receiveQueue.TryGetValue(message.MessageID, out var state))
            {
                state.Responses.Post(ldapMessage);
            }
            else if (message.MessageID == 0)
            {
                throw new NotImplementedException("Unsolicited Notification");
            }
            else
            {
                throw new NotImplementedException("unexpected messageId");
            }
        }
        
        private async Task ReadAsync(CancellationToken cancellationToken)
        {
            var writer = _pipe.Writer;
            try
            {
                using (var socket = _client.Client)
                while (!_closed && socket.Connected)
                {
                    var buffer = writer.GetMemory(1024);
                    var read = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                        break;
                    writer.Advance(read);
                    var flushed = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (flushed.IsCompleted)
                        break;
                }
                writer.Complete();
            }
            catch (OperationCanceledException ex)
            {
                writer.Complete(ex);
            }
            catch (SocketException ex)
            {
                writer.Complete(ex);
            }
        }

        private bool _disposed = false;
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {
                _closed = true;
                _closeTokenSource.Cancel();
                _client.Dispose();
                if (_reader != null && _reader.IsCompleted)
                    _reader.Dispose();
                if (_dispatcher != null && _dispatcher.IsCompleted)
                    _dispatcher.Dispose();
                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private int NextMessageId()
        {
            return Interlocked.Increment(ref _messageId);
        }

        private sealed class MessageState
        {
            public BufferBlock<LdapRequestMessage> Responses { get; }

            public MessageState(int messageId, CancellationToken cancellationToken)
            {
                MessageId = messageId;
                Responses = new BufferBlock<LdapRequestMessage>(new DataflowBlockOptions
                {
                    CancellationToken =  cancellationToken,
                    EnsureOrdered = true,
                });
            }
            
            public int MessageId { get; }

            public async Task<LdapRequestMessage> ReceiveAsync(CancellationToken cancellationToken)
            {
                return await Responses.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
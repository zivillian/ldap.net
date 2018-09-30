using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
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
        private readonly Pipe _pipe;
        private readonly AsnWriter _writer;
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
            _writer = new AsnWriter(AsnEncodingRules.BER);
            _writeLock = new SemaphoreSlim(1, 1);
            _closeTokenSource = new CancellationTokenSource();
            _pipe = new Pipe();
        }

        public DerefAliases Deref { get; set; }

        public int SizeLimit
        {
            get => _sizeLimit;
            set
            {
                if (_sizeLimit < 0)
                    throw new ArgumentOutOfRangeException();
                _sizeLimit = value;
            }
        }

        public TimeSpan TimeLimit
        {
            get => _timeLimit;
            set
            {
                if (_timeLimit < TimeSpan.Zero)
                    throw new ArgumentOutOfRangeException();
                _timeLimit = value;
            }
        }

        public bool Referrals { get; set; } = true;
        
        public string Hostname { get; }

        public ushort Port { get; }

        public List<LdapControl> ServerControls { get; }

        public async Task SimpleBindAsync(string dn, string password, CancellationToken cancellationToken)
        {
            var messageId = Interlocked.Increment(ref _messageId);
            var request = new LdapBindRequest(messageId, dn, password, ServerControls.ToArray());
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            var bindResponse = (LdapBindResponse) response;
            if (bindResponse.ResultCode != ResultCode.Success)
                throw new LdapServerException(bindResponse);
        }

        public async Task UnbindAsync(CancellationToken cancellationToken)
        {
            var messageId = Interlocked.Increment(ref _messageId);
            var request = new LdapUnbindRequest(messageId, ServerControls.ToArray());
            await SendWithoutResponseAsync(request, cancellationToken).ConfigureAwait(false);
            Dispose(true);
        }

        private async Task SendWithoutResponseAsync(LdapRequestMessage request, CancellationToken cancellationToken)
        {
            await ConnectAsync().ConfigureAwait(false);

            var asn = request.GetAsn();
            var stream = _client.GetStream();
            try
            {
                await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                asn.Encode(_writer);
                var bytes = (ReadOnlyMemory<byte>) _writer.Encode();
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
            using (var state = new MessageState(request.Id))
            {
                _receiveQueue.AddOrUpdate(state.MessageId, state, (i, o) => throw new InvalidOperationException());
                await SendWithoutResponseAsync(request, cancellationToken).ConfigureAwait(false);
                var result = await state.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                if (!_receiveQueue.TryRemove(state.MessageId, out _))
                    throw new InvalidOperationException();
                return result;
            }
        }

        private async Task ConnectAsync()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);
            if (_client.Connected) return;

            if (Hostname.Contains(' '))
                throw new NotImplementedException();

            await _client.ConnectAsync(Hostname, Port).ConfigureAwait(false);
            _reader = ReadAsync(_closeTokenSource.Token);
            _dispatcher = DispatchAsync(_closeTokenSource.Token);
        }

        private async Task DispatchAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                var result = await _pipe.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                var buffer = result.Buffer;

                if (buffer.IsSingleSegment)
                {
                    if (AsnReader.TryPeekTag(buffer.First.Span, out var tag, out var bytesRead))
                    {
                        if (AsnReader.TryReadLength(buffer.First.Span.Slice(bytesRead), AsnEncodingRules.BER, out var length, out var lengthBytesRead))
                        {
                            if (length.HasValue && buffer.Length > length)
                            {
                                var tagLength = length.Value + bytesRead + lengthBytesRead;
                                var message = Asn1Serializer.Deserialize(buffer.First.Slice(0, tagLength));
                                OnMessageReceived(message);
                            }
                        }
                    }
                }
                else
                {
                    throw new NotImplementedException();
                }
                    

                if (result.IsCompleted)
                    break;
            }
        }

        private void OnMessageReceived(Asn1LdapMessage message)
        {
            if (_receiveQueue.TryGetValue(message.MessageID, out var state))
            {
                state.Response = LdapRequestMessage.Create(message);
            }
            else
            {
                throw new NotImplementedException();
            }
        }
        
        private async Task ReadAsync(CancellationToken cancellationToken)
        {
            try
            {
                using (var stream = _client.GetStream())
                while (!_closed)
                {
                    var buffer = _pipe.Writer.GetMemory(1024);
                    var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                        break;
                    _pipe.Writer.Advance(read);
                    await _pipe.Writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                _pipe.Writer.Complete();
            }
            catch (Exception ex)
            {
                _pipe.Writer.Complete(ex);
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
                if (_reader.IsCompleted)
                    _reader.Dispose();
                if (_dispatcher.IsCompleted)
                    _dispatcher.Dispose();
                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private sealed class MessageState:IDisposable
        {
            private readonly SemaphoreSlim _resetEvent;

            private LdapRequestMessage _response;

            private bool _disposed;

            public MessageState(int messageId)
            {
                MessageId = messageId;
                _resetEvent = new SemaphoreSlim(0, 1);
            }
            
            public int MessageId { get; }

            public LdapRequestMessage Response
            {
                get { return _response; }
                set
                {
                    if (_disposed) return;
                    _response = value;
                    _resetEvent.Release();
                }
            }

            public async Task<LdapRequestMessage> ReceiveAsync(CancellationToken cancellationToken)
            {
                await _resetEvent.WaitAsync(cancellationToken).ConfigureAwait(false);
                return Response;
            }

            public void Dispose()
            {
                _resetEvent.Dispose();
                _disposed = true;
            }
        }
    }
}
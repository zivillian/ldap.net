using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace zivillian.ldap
{
    public class LdapClientConnection:IDisposable
    {
        private readonly CancellationTokenSource _cts;
        private readonly ConcurrentDictionary<int, LdapRequest> _pending;
        private readonly SemaphoreSlim _lock;
        private readonly SemaphoreSlim _bindLock;
        private readonly TcpClient _client;
        private readonly Stream _stream;

        public LdapClientConnection(TcpClient client, Stream stream, Pipe pipe, CancellationTokenSource cts)
        {
            Id = Guid.NewGuid();
            _client = client;
            _stream = stream;
            Pipe = pipe;
            _cts = cts;
            CancellationToken = _cts.Token;
            _pending = new ConcurrentDictionary<int, LdapRequest>();
            _lock = new SemaphoreSlim(1, 1);
            _bindLock = new SemaphoreSlim(1, 1);
        }

        public Guid Id { get; }
        
        public Pipe Pipe { get; }


        public Stream Stream
        {
            get { return _stream; }
        }

        public PipeReader Reader
        {
            get { return Pipe.Reader; }
        }

        public PipeWriter Writer
        {
            get { return Pipe.Writer; }
        }

        public bool IsConnected
        {
            get { return _client.Connected; }
        }

        public CancellationToken CancellationToken { get; }

        internal async Task<bool> TryAddPendingAsync(LdapRequestMessage message)
        {
            await _bindLock.WaitAsync(CancellationToken).ConfigureAwait(false);
            try
            {
                return _pending.TryAdd(message.Id, new LdapRequest(message, CancellationToken));
            }
            finally
            {
                _bindLock.Release();
            }
        }

        internal void RemovePending(LdapRequestMessage message)
        {
            if (_pending.TryRemove(message.Id, out var request))
            {
                request.Dispose();
            }
        }

        internal async Task WriteAsync(byte[] data)
        {
            await _lock.WaitAsync(CancellationToken).ConfigureAwait(false);
            try
            {
                await Stream.WriteAsync(data, CancellationToken);
            }
            finally
            {
                _lock.Release();
            }
        }

        internal void AbandonRequest(int messageId)
        {
            if(_pending.TryGetValue(messageId, out var message))
            {
                using (message)
                {
                    message.Cancel();
                }
                _pending.TryRemove(messageId, out message);
            }
        }

        internal async Task BeginBindAsync()
        {
            await _bindLock.WaitAsync(CancellationToken).ConfigureAwait(false);
            foreach (var request in _pending.Values)
            {
                AbandonRequest(request.Request.Id);
                CancellationToken.ThrowIfCancellationRequested();
            }
        }

        internal void FinishBind()
        {
            _bindLock.Release();
        }

        internal void CloseConnection()
        {
            if (!_cts.IsCancellationRequested)
                _cts.Cancel();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _lock?.Dispose();
                foreach (var request in _pending.Values)
                {
                    request.Dispose();
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private class LdapRequest:IDisposable
        {
            private CancellationTokenSource _cts;

            public LdapRequest(LdapRequestMessage request, CancellationToken cancellationToken)
            {
                Request = request;
                _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            }

            public LdapRequestMessage Request { get; }

            public void Cancel()
            {
                _cts.Cancel();
            }

            protected virtual void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _cts?.Dispose();
                }
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
        }
    }
}
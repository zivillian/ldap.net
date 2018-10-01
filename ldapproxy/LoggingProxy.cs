using System;

namespace zivillian.ldap.proxy
{
    public class LoggingProxy:LdapProxy
    {
        public LoggingProxy(ushort localPort, string hostname, ushort port) 
            : base(localPort, hostname, port)
        {
        }

        protected override LdapRequestMessage OnSendToClient(Guid clientId, LdapRequestMessage message)
        {
            if (message is ILdapResult result)
                Console.WriteLine($"{clientId} S {message.Id:D4} : {message.GetType().Name} ({result.ResultCode})");
            else
                Console.WriteLine($"{clientId} R {message.Id:D4} : {message.GetType().Name}");
            return base.OnSendToClient(clientId, message);
        }

        protected override LdapRequestMessage OnSendToServer(Guid clientId, LdapRequestMessage message)
        {
            if (message is ILdapResult result)
                Console.WriteLine($"{clientId} S {message.Id:D4} : {message.GetType().Name} ({result.ResultCode})");
            else
                Console.WriteLine($"{clientId} S {message.Id:D4} : {message.GetType().Name}");
            return base.OnSendToServer(clientId, message);
        }

        protected override void OnError(Guid clientId, LdapException exception)
        {
            Console.WriteLine($"{clientId} E {exception.Message} ({exception.ResultCode})");
            base.OnError(clientId, exception);
        }
    }
}
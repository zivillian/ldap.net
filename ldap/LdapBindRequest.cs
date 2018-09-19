using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindRequest : LdapRequestMessage
    {
        public int Version { get; }

        public string Name { get; }

        public ReadOnlyMemory<byte> Simple { get; }

        public string SaslMechanism { get; }

        public ReadOnlyMemory<byte>? SaslCredentials { get; }

        internal LdapBindRequest(Asn1LdapMessage message)
            : base(message)
        {
            var bindRequest = message.ProtocolOp.BindRequest.Value;
            Version = bindRequest.Version;
            Name = Encoding.UTF8.GetString(bindRequest.Name.Span);
            var auth = bindRequest.Authentication;
            if (auth.Simple != null)
            {
                Simple = auth.Simple.Value.ToArray();
            }
            else if (auth.Sasl != null)
            {
                var sasl = auth.Sasl.Value;
                SaslMechanism = Encoding.UTF8.GetString(sasl.Mechanism.Span);
                SaslCredentials = sasl.Credentials;
            }
        }
    }
}
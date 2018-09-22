using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindRequest : LdapRequestMessage
    {
        public byte Version { get; }

        public string Name { get; }

        public ReadOnlyMemory<byte>? Simple { get; }

        public string SaslMechanism { get; }

        public ReadOnlyMemory<byte>? SaslCredentials { get; }

        internal LdapBindRequest(Asn1LdapMessage message)
            : base(message)
        {
            var bindRequest = message.ProtocolOp.BindRequest;
            Version = bindRequest.Version;
            Name = Encoding.UTF8.GetString(bindRequest.Name.Span);
            var auth = bindRequest.Authentication;
            if (auth.Simple != null)
            {
                Simple = auth.Simple.Value.ToArray();
            }
            else if (auth.Sasl != null)
            {
                var sasl = auth.Sasl;
                SaslMechanism = Encoding.UTF8.GetString(sasl.Mechanism.Span);
                SaslCredentials = sasl.Credentials;
            }
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var bindRequest = op.BindRequest = new Asn1BindRequest
            {
                Version = Version,
                Name = Encoding.UTF8.GetBytes(Name),
                Authentication = new Asn1AuthenticationChoice()
            };
            if (Simple.HasValue)
            {
                bindRequest.Authentication.Simple = Simple.Value;
            }
            else if (SaslMechanism != null)
            {
                var sasl = new Asn1SaslCredentials
                {
                    Mechanism = Encoding.UTF8.GetBytes(SaslMechanism),
                    Credentials = SaslCredentials
                };
                bindRequest.Authentication.Sasl = sasl;
            }
        }
    }
}
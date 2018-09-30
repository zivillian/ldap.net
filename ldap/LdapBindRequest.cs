using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindRequest : LdapRequestMessage
    {
        public byte Version { get; }

        public LdapDistinguishedName Name { get; }

        public ReadOnlyMemory<byte>? Simple { get; }

        public string SaslMechanism { get; }

        public ReadOnlyMemory<byte>? SaslCredentials { get; }

        internal LdapBindRequest(Asn1LdapMessage message)
            : base(message)
        {
            var bindRequest = message.ProtocolOp.BindRequest;
            Version = bindRequest.Version;
            if (Version < 1 || Version > 127)
                throw new ArgumentException("invalid LDAP version");
            Name = new LdapDistinguishedName(bindRequest.Name.Span);
            var auth = bindRequest.Authentication;
            if (auth.Simple != null)
            {
                Simple = auth.Simple.Value.ToArray();
            }
            else if (auth.Sasl != null)
            {
                var sasl = auth.Sasl;
                SaslMechanism = sasl.Mechanism.Span.LdapString();
                SaslCredentials = sasl.Credentials;
            }
        }

        internal LdapBindRequest(int messageId, string dn, string password, LdapControl[] controls)
            : base(messageId, controls)
        {
            Version = 3;
            Name = new LdapDistinguishedName(dn);
            Simple = password.LdapString();
        }

        internal LdapBindRequest(int messageId, string dn, string mechanism, ReadOnlyMemory<byte> credentials, LdapControl[] controls)
        :base(messageId, controls)
        {
            Version = 3;
            Name = new LdapDistinguishedName(dn);
            SaslMechanism = mechanism;
            SaslCredentials = credentials;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var bindRequest = op.BindRequest = new Asn1BindRequest
            {
                Version = Version,
                Name = Name.GetBytes(),
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
                    Mechanism = SaslMechanism.LdapString(),
                    Credentials = SaslCredentials
                };
                bindRequest.Authentication.Sasl = sasl;
            }
        }
    }
}
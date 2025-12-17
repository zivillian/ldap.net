using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindRequest : LdapRequestMessage
    {
        public byte Version { get; }

        public LdapDistinguishedName Name { get; }

        public ReadOnlyMemory<byte>? Simple { get; }

        public string? SaslMechanism { get; }

        public ReadOnlyMemory<byte>? SaslCredentials { get; }

        internal LdapBindRequest(Asn1BindRequest bindRequest, Asn1LdapMessage message)
            : base(message)
        {
            var version = bindRequest.Version;
            if (version < 1 || version > 127)
                throw new ArgumentException("invalid LDAP version");
            Version = (byte)version;
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

        public LdapBindRequest(int messageId, string dn, string password, LdapControl[] controls)
            : base(messageId, controls)
        {
            Version = 3;
            Name = new LdapDistinguishedName(dn);
            Simple = password.LdapString();
        }

        public LdapBindRequest(int messageId, string dn, string mechanism, ReadOnlyMemory<byte> credentials, LdapControl[] controls)
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
            (
                Version,
                Name.GetBytes(),
                new Asn1AuthenticationChoice()
            );
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

        public LdapBindResponse Response()
        {
            return Response(ResultCode.Success, String.Empty);
        }

        public LdapBindResponse Response(ResultCode resultCode, string message)
        {
            return new LdapBindResponse(Id, resultCode, LdapDistinguishedName.Empty, message, Array.Empty<string>());
        }
    }
}
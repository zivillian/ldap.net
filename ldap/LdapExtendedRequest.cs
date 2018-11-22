using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtendedRequest : LdapRequestMessage
    {
        public const string StartTLS = "1.3.6.1.4.1.1466.20037";

        public string Name { get; }

        public ReadOnlyMemory<byte>? Value { get; }

        internal LdapExtendedRequest(Asn1LdapMessage message)
            : base(message)
        {
            var extended = message.ProtocolOp.ExtendedRequest;
            Name = extended.Name.Span.NumericOid();
            Value = extended.Value;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ExtendedRequest = new Asn1ExtendedRequest
            {
                Name = Name.NumericOid(),
                Value = Value
            };
        }

        public LdapExtendedResponse NotSupported()
        {
            return new LdapExtendedResponse(Id, ResultCode.ProtocolError, String.Empty, Array.Empty<LdapControl>());
        }

        public LdapExtendedResponse StartTlsResponse()
        {
            return new LdapExtendedResponse(Id, StartTLS);
        }
    }
}
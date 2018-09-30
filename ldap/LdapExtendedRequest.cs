using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtendedRequest : LdapRequestMessage
    {
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
    }
}
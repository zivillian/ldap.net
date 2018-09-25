using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapIntermediateResponse : LdapRequestMessage
    {
        public string Name { get; }
        
        public ReadOnlyMemory<byte>? Value { get; }

        internal LdapIntermediateResponse(Asn1LdapMessage message) : base(message)
        {
            var intermediate = message.ProtocolOp.IntermediateResponse;
            if (intermediate.Name.HasValue)
                Name = intermediate.Name.Value.Span.LdapOid();
            Value = intermediate.Value;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.IntermediateResponse = new Asn1IntermediateResponse
            {
                Value = Value
            };
            if (Name != null)
                op.IntermediateResponse.Name = Name.LdapOid();
        }
    }
}
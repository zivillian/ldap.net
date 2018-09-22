using System;
using System.Text;
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
            Name = Encoding.UTF8.GetString(extended.Name.Span);
            Value = extended.Value;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ExtendedRequest = new Asn1ExtendedRequest
            {
                Name = Encoding.UTF8.GetBytes(Name),
                Value = Value
            };
        }
    }
}
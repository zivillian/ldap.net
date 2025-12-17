using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapDeleteRequest : LdapRequestMessage
    {
        public LdapDistinguishedName DN { get; }

        internal LdapDeleteRequest(ReadOnlyMemory<byte> request, Asn1LdapMessage message)
            : base(message)
        {
            DN = new LdapDistinguishedName(request.Span);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.DelRequest = DN.GetBytes();
        }
    }
}
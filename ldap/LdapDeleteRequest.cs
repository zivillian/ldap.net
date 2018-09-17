using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapDeleteRequest : LdapRequestMessage
    {
        public string DN { get; }

        internal LdapDeleteRequest(Asn1LdapMessage message)
            : base(message)
        {
            DN = Encoding.UTF8.GetString(message.ProtocolOp.DelRequest.Value.Span);
        }
    }
}
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapUnbindRequest : LdapRequestMessage
    {
        internal LdapUnbindRequest(Asn1LdapMessage message)
            : base(message)
        {
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.UnbindRequest = true;
        }
    }
}
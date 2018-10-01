using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapDeleteResponse : LdapResponseMessage
    {
        internal LdapDeleteResponse(Asn1LdapMessage message)
            : base(message.ProtocolOp.DelResponse, message)
        {
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result)
        {
            op.DelResponse = result;
        }
    }
}
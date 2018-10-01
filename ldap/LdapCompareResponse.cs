using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapCompareResponse : LdapResponseMessage
    {
        internal LdapCompareResponse(Asn1LdapMessage message)
            : base(message.ProtocolOp.CompareResponse, message)
        {
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result)
        {
            op.CompareResponse = result;
        }
    }
}
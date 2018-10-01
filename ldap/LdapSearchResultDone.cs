using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchResultDone : LdapResponseMessage
    {
        internal LdapSearchResultDone(Asn1LdapMessage message)
            : base(message.ProtocolOp.SearchResultDone, message)
        {
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result)
        {
            op.SearchResultDone = result;
        }
    }
}
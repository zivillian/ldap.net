using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchResultDone : LdapResponseMessage
    {
        internal LdapSearchResultDone(Asn1LdapMessage message)
            : base(message.ProtocolOp.SearchResultDone, message)
        {
        }

        internal LdapSearchResultDone(int id, ResultCode resultCode, LdapDistinguishedName matchedDN, string message,
            string[] referrals, LdapControl[] controls)
        :base(id, resultCode, matchedDN, message, referrals, controls)
        {

        }

        internal override void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result)
        {
            op.SearchResultDone = result;
        }
    }
}
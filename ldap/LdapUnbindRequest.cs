using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapUnbindRequest : LdapRequestMessage
    {
        internal LdapUnbindRequest(Asn1LdapMessage message)
            : base(message)
        {
        }
    }
}
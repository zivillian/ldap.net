using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchResultReference : LdapRequestMessage
    {
        public string[] Uris { get; }

        internal LdapSearchResultReference(Asn1LdapMessage message)
            : base(message)
        {
            Uris = LdapResultExtensions.GetReferrals(message.ProtocolOp.SearchResultReference);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.SearchResultReference = LdapResultExtensions.GetReferrals(Uris);
        }
    }
}
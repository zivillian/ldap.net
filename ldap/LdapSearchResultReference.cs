using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchResultReference : LdapRequestMessage
    {
        public IReadOnlyList<string> Uris { get; }

        internal LdapSearchResultReference(ReadOnlyMemory<byte>[] referral,
            Asn1LdapMessage message)
            : base(message)
        {
            Uris = LdapResultExtensions.GetReferrals(referral);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.SearchResultReference = LdapResultExtensions.GetReferrals(Uris);
        }
    }
}
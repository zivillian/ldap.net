using System;
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

    public class LdapSearchResultDone : LdapResponseMessage
    {
        internal LdapSearchResultDone(ResultCode resultCode, ReadOnlyMemory<byte> matchedDN, ReadOnlyMemory<byte> diagnosticMessage, ReadOnlyMemory<byte>[] referral, Asn1LdapMessage message)
            : base(resultCode, matchedDN, diagnosticMessage, referral, message)
        {
        }
    }
}
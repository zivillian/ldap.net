using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindResponse:LdapResponseMessage
    {
        public ReadOnlyMemory<byte>? ServerSaslCreds { get; }

        internal LdapBindResponse(Asn1BindResponse bindResponse, Asn1LdapMessage message)
            : base(bindResponse.ResultCode, bindResponse.MatchedDN, bindResponse.DiagnosticMessage,
                bindResponse.Referral, message)
        {
            ServerSaslCreds = bindResponse.ServerSaslCreds;
        }
    }
}
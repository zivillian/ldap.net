using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindResponse:LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; internal set; }

        public LdapDistinguishedName MatchedDN { get; internal set; }

        public string DiagnosticMessage { get; internal set; }
        
        public string[] Referrals { get; internal set; }

        public ReadOnlyMemory<byte>? ServerSaslCreds { get; }

        internal LdapBindResponse(Asn1BindResponse bindResponse, Asn1LdapMessage message)
            : base(message)
        {
            ResultCode = bindResponse.ResultCode;
            MatchedDN = new LdapDistinguishedName(bindResponse.MatchedDN.Span);
            DiagnosticMessage = bindResponse.DiagnosticMessage.Span.LdapString();
            Referrals = this.GetReferrals(bindResponse.Referral);
            ServerSaslCreds = bindResponse.ServerSaslCreds;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.BindResponse = new Asn1BindResponse
            {
                ResultCode = ResultCode,
                MatchedDN = MatchedDN.GetBytes(),
                DiagnosticMessage = DiagnosticMessage.LdapString(),
                Referral = this.GetReferrals(Referrals),
                ServerSaslCreds = ServerSaslCreds
            };
        }
    }
}
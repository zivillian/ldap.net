using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapBindResponse:LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; internal set; }

        public string MatchedDN { get; internal set; }

        public string DiagnosticMessage { get; internal set; }
        
        public string[] Referrals { get; internal set; }

        public ReadOnlyMemory<byte>? ServerSaslCreds { get; }

        internal LdapBindResponse(Asn1BindResponse bindResponse, Asn1LdapMessage message)
            : base(message)
        {
            ResultCode = bindResponse.ResultCode;
            MatchedDN = Encoding.UTF8.GetString(bindResponse.MatchedDN.Span);
            DiagnosticMessage = Encoding.UTF8.GetString(bindResponse.DiagnosticMessage.Span);
            Referrals = this.GetReferrals(bindResponse.Referral);
            ServerSaslCreds = bindResponse.ServerSaslCreds;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.BindResponse = new Asn1BindResponse
            {
                ResultCode = ResultCode,
                MatchedDN = Encoding.UTF8.GetBytes(MatchedDN),
                DiagnosticMessage = Encoding.UTF8.GetBytes(DiagnosticMessage),
                Referral = this.GetReferrals(Referrals),
                ServerSaslCreds = ServerSaslCreds
            };
        }
    }
}
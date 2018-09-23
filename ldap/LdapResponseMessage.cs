using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapResponseMessage:LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; internal set; }

        public LdapDistinguishedName MatchedDN { get; internal set; }

        public string DiagnosticMessage { get; internal set; }
        
        public string[] Referrals { get; internal set; }

        internal LdapResponseMessage(Asn1LDAPResult result, Asn1LdapMessage message)
            : base(message)
        {
            
            ResultCode = result.ResultCode;
            MatchedDN = new LdapDistinguishedName(result.MatchedDN.Span);
            DiagnosticMessage = Encoding.UTF8.GetString(result.DiagnosticMessage.Span);
            Referrals = this.GetReferrals(result.Referral);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var asn = new Asn1LDAPResult
            {
                ResultCode = ResultCode,
                MatchedDN = MatchedDN.GetBytes(),
                DiagnosticMessage = Encoding.UTF8.GetBytes(DiagnosticMessage),
                Referral = this.GetReferrals(Referrals),
            };
            SetProtocolOp(op, asn);
        }

        internal abstract void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result);
    }
}
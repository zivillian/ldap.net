using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapResponseMessage:LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; internal set; }

        public LdapDistinguishedName MatchedDN { get; internal set; }

        public string DiagnosticMessage { get; internal set; }
        
        public IReadOnlyList<string> Referrals { get; internal set; }

        internal LdapResponseMessage(Asn1LDAPResult result, Asn1LdapMessage message)
            : base(message)
        {
            ResultCode = result.ResultCode;
            MatchedDN = new LdapDistinguishedName(result.MatchedDN.Span);
            DiagnosticMessage = result.DiagnosticMessage.Span.LdapString();
            Referrals = this.GetReferrals(result.Referral);
        }

        internal LdapResponseMessage(int messageId, ResultCode resultCode, LdapDistinguishedName matchedDN,
            string message, string[] referrals, LdapControl[] controls)
            :base(messageId, controls)
        {
            ResultCode = resultCode;
            MatchedDN = matchedDN;
            DiagnosticMessage = message;
            Referrals = referrals;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var asn = new Asn1LDAPResult
            {
                ResultCode = ResultCode,
                MatchedDN = MatchedDN.GetBytes(),
                DiagnosticMessage = DiagnosticMessage.LdapString(),
                Referral = this.GetReferrals(Referrals),
            };
            SetProtocolOp(op, asn);
        }

        internal abstract void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result);
    }
}
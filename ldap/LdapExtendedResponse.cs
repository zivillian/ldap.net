using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtendedResponse : LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; }

        public LdapDistinguishedName MatchedDN { get; }

        public string DiagnosticMessage { get; }

        public IReadOnlyList<string> Referrals { get; }

        public string Name { get; }

        public ReadOnlyMemory<byte>? Value { get; }

        internal LdapExtendedResponse(Asn1LdapMessage message)
            : base(message)
        {
            var extended = message.ProtocolOp.ExtendedResponse;
            ResultCode = extended.ResultCode;
            MatchedDN = new LdapDistinguishedName(extended.MatchedDN.Span);
            DiagnosticMessage = extended.DiagnosticMessage.Span.LdapString();
            Referrals = this.GetReferrals(extended.Referral);
            if (extended.Name.HasValue)
                Name = extended.Name.Value.Span.NumericOid();
            Value = extended.Value;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ExtendedResponse = new Asn1ExtendedResponse
            {
                ResultCode = ResultCode,
                MatchedDN = MatchedDN.GetBytes(),
                DiagnosticMessage = DiagnosticMessage.LdapString(),
                Referral = this.GetReferrals(Referrals),
                Value = Value
            };
            if (Name != null)
            {
                op.ExtendedResponse.Name = Name.NumericOid();
            }
        }

    }
}
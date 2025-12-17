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

        public string? Name { get; }

        public ReadOnlyMemory<byte>? Value { get; }

        internal LdapExtendedResponse(Asn1ExtendedResponse extended, Asn1LdapMessage message)
            : base(message)
        {
            ResultCode = extended.ResultCode;
            MatchedDN = new LdapDistinguishedName(extended.MatchedDN.Span);
            DiagnosticMessage = extended.DiagnosticMessage.Span.LdapString();
            Referrals = this.GetReferrals(extended.Referral);
            if (extended.Name.HasValue)
                Name = extended.Name.Value.Span.NumericOid();
            Value = extended.Value;
        }

        internal LdapExtendedResponse(int id, string name):
            this(id, ResultCode.Success, String.Empty, Array.Empty<LdapControl>())
        {
            Name = name;
        }

        internal LdapExtendedResponse(int id, ResultCode resultCode, string message, LdapControl[] controls)
            : base(id, controls)
        {
            ResultCode = resultCode;
            DiagnosticMessage = message;
            MatchedDN = LdapDistinguishedName.Empty;
            Referrals = Array.Empty<string>();
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
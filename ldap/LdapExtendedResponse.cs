using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtendedResponse : LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; }

        public LdapDistinguishedName MatchedDN { get; }

        public string DiagnosticMessage { get; }

        public string[] Referrals { get; }

        public string Name { get; }

        public ReadOnlyMemory<byte>? Value { get; }

        internal LdapExtendedResponse(Asn1LdapMessage message)
            : base(message)
        {
            var extended = message.ProtocolOp.ExtendedResponse;
            ResultCode = extended.ResultCode;
            MatchedDN = new LdapDistinguishedName(extended.MatchedDN.Span);
            DiagnosticMessage = Encoding.UTF8.GetString(extended.DiagnosticMessage.Span);
            Referrals = this.GetReferrals(extended.Referral);
            if (extended.Name.HasValue)
                Name = extended.Name.Value.Span.LdapOid();
            Value = extended.Value;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ExtendedResponse = new Asn1ExtendedResponse
            {
                ResultCode = ResultCode,
                MatchedDN = MatchedDN.GetBytes(),
                DiagnosticMessage = Encoding.UTF8.GetBytes(DiagnosticMessage),
                Referral = this.GetReferrals(Referrals),
                Value = Value
            };
            if (Name != null)
            {
                op.ExtendedResponse.Name = Name.LdapOid();
            }
        }

    }
}
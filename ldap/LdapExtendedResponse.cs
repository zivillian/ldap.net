using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtendedResponse : LdapRequestMessage, ILdapResult
    {
        public ResultCode ResultCode { get; }

        public string MatchedDN { get; }

        public string DiagnosticMessage { get; }

        public string[] Referrals { get; }

        public string Name { get; }

        public ReadOnlyMemory<byte>? Value { get; }

        internal LdapExtendedResponse(Asn1LdapMessage message)
            : base(message)
        {
            var extended = message.ProtocolOp.ExtendedResponse;
            ResultCode = extended.ResultCode;
            MatchedDN = Encoding.UTF8.GetString(extended.MatchedDN.Span);
            DiagnosticMessage = Encoding.UTF8.GetString(extended.DiagnosticMessage.Span);
            Referrals = this.GetReferrals(extended.Referral);
            if (extended.Name.HasValue)
                Name = Encoding.UTF8.GetString(extended.Name.Value.Span);
            Value = extended.Value;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ExtendedResponse = new Asn1ExtendedResponse
            {
                ResultCode = ResultCode,
                MatchedDN = Encoding.UTF8.GetBytes(MatchedDN),
                DiagnosticMessage = Encoding.UTF8.GetBytes(DiagnosticMessage),
                Referral = this.GetReferrals(Referrals),
                Value = Value
            };
            if (Name != null)
            {
                op.ExtendedResponse.Name = Encoding.UTF8.GetBytes(Name);
            }
        }

    }
}
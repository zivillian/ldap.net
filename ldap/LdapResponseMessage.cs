using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapResponseMessage:LdapRequestMessage
    {
        public ResultCode ResultCode { get; }

        public string MatchedDN { get; }

        public string DiagnosticMessage { get; }
        
        public string[] Referrals { get; }

        internal LdapResponseMessage(ResultCode resultCode, ReadOnlyMemory<byte> matchedDN, 
            ReadOnlyMemory<byte> diagnosticMessage, ReadOnlyMemory<byte>[] referral, 
            Asn1LdapMessage message)
            : base(message)
        {
            ResultCode = resultCode;
            MatchedDN = Encoding.UTF8.GetString(matchedDN.Span);
            DiagnosticMessage = Encoding.UTF8.GetString(diagnosticMessage.Span);
            Referrals = new string[0];
            if (referral != null)
            {
                Referrals = new string[referral.Length];
                for (int i = 0; i < referral.Length; i++)
                {
                    Referrals[i] = Encoding.UTF8.GetString(referral[i].Span);
                }
            }
        }
    }

    public class LdapSearchResultEntry : LdapRequestMessage
    {
        public string ObjectName { get; }

        public string[] Attributes { get{throw new NotImplementedException();} }

        internal LdapSearchResultEntry(Asn1LdapMessage message)
            : base(message)
        {
            var search = message.ProtocolOp.SearchResEntry.Value;
            ObjectName = Encoding.UTF8.GetString(search.ObjectName.Span);
        }
    }
}
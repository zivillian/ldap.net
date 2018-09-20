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

        public LdapAttribute[] Attributes { get; }

        internal LdapSearchResultEntry(Asn1LdapMessage message)
            : base(message)
        {
            var search = message.ProtocolOp.SearchResEntry;
            ObjectName = Encoding.UTF8.GetString(search.ObjectName.Span);
            Attributes = new LdapAttribute[0];
            if (search.Attributes.Length > 0)
            {
                Attributes = new LdapAttribute[search.Attributes.Length];
                for (int i = 0; i < search.Attributes.Length; i++)
                {
                    Attributes[i] = new LdapAttribute(search.Attributes[i]);
                }
            }
        }
    }

    public class LdapAttribute
    {
        public string Type { get; }

        public string[] Values { get; }

        internal LdapAttribute(Asn1PartialAttribute attribute)
        {
            Type = Encoding.UTF8.GetString(attribute.Type.Span);
            Values= new string[0];
            if (attribute.Values.Length > 0)
            {
                Values = new string[attribute.Values.Length];
                for (int i = 0; i < attribute.Values.Length; i++)
                {
                    Values[i] = Encoding.UTF8.GetString(attribute.Values[i].Span);
                }
            }
        }
    }
}
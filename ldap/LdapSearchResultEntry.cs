using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchResultEntry : LdapRequestMessage
    {
        public LdapDistinguishedName ObjectName { get; }

        public LdapAttribute[] Attributes { get; }

        internal LdapSearchResultEntry(Asn1LdapMessage message)
            : base(message)
        {
            var search = message.ProtocolOp.SearchResEntry;
            ObjectName = new LdapDistinguishedName(search.ObjectName.Span);
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

        internal LdapSearchResultEntry(int messageId, LdapDistinguishedName objectName, LdapAttribute[] attributes, LdapControl[] controls)
        :base(messageId, controls)
        {
            ObjectName = objectName;
            Attributes = attributes;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var result = new Asn1SearchResultEntry
            {
                ObjectName = ObjectName.GetBytes(),
                Attributes = new Asn1PartialAttribute[0]
            };
            if (Attributes != null && Attributes.Length > 0)
            {
                result.Attributes = new Asn1PartialAttribute[Attributes.Length];
                for (int i = 0; i < Attributes.Length; i++)
                {
                    var attribute = Attributes[i];
                    result.Attributes[i] = attribute.GetAsn();
                }
            }
            op.SearchResEntry = result;
        }
    }
}
using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchResultEntry : LdapRequestMessage
    {
        public LdapDistinguishedName ObjectName { get; }

        public IReadOnlyList<LdapAttribute> Attributes { get; }

        internal LdapSearchResultEntry(Asn1LdapMessage message)
            : base(message)
        {
            var search = message.ProtocolOp.SearchResEntry;
            ObjectName = new LdapDistinguishedName(search.ObjectName.Span);
            if (search.Attributes.Length > 0)
            {
                var attributes = new LdapAttribute[search.Attributes.Length];
                for (int i = 0; i < search.Attributes.Length; i++)
                {
                    attributes[i] = new LdapAttribute(search.Attributes[i]);
                }
                Attributes = attributes;
            }
            else
            {
                Attributes = Array.Empty<LdapAttribute>();
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
                Attributes = Array.Empty<Asn1PartialAttribute>()
            };
            if (Attributes != null && Attributes.Count > 0)
            {
                result.Attributes = new Asn1PartialAttribute[Attributes.Count];
                for (int i = 0; i < Attributes.Count; i++)
                {
                    var attribute = Attributes[i];
                    result.Attributes[i] = attribute.GetAsn();
                }
            }
            op.SearchResEntry = result;
        }
    }
}
using System;
using System.IO;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAttribute
    {
        public LdapAttributeDescription Type { get; }

        public ReadOnlyMemory<byte>[] Values { get; }

        internal LdapAttribute(Asn1PartialAttribute attribute)
        {
            Type = new LdapAttributeDescription(attribute.Type.Span);
            Values = attribute.Values;
        }

        internal Asn1PartialAttribute GetAsn()
        {
            var result = new Asn1PartialAttribute
            {
                Type = Type.GetBytes(),
                Values = Values
            };
            return result;
        }
    }
}
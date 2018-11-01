using System;
using System.Collections.Generic;
using System.Linq;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAttribute
    {
        public LdapAttributeDescription Type { get; }

        public virtual IReadOnlyList<ReadOnlyMemory<byte>> Values { get; }

        internal LdapAttribute(Asn1PartialAttribute attribute)
        {
            Type = new LdapAttributeDescription(attribute.Type.Span);
            Values = attribute.Values;
        }

        public LdapAttribute(ReadOnlySpan<char> type, ReadOnlyMemory<byte>[] values)
            :this(new LdapAttributeDescription(type), values)
        {
        }

        public LdapAttribute(LdapAttributeDescription type, ReadOnlyMemory<byte>[] values)
        {
            if (values is null)
                throw new ArgumentNullException(nameof(values));

            Type = type;
            Values = values;
        }

        internal Asn1PartialAttribute GetAsn()
        {
            var result = new Asn1PartialAttribute
            {
                Type = Type.GetBytes(),
                Values = Values.ToArray()
            };
            return result;
        }
    }
}
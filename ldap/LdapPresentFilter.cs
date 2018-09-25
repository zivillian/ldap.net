using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapPresentFilter : LdapFilter
    {
        public LdapAttributeDescription Attribute { get; }

        internal LdapPresentFilter(ReadOnlyMemory<byte> attribute)
        {
            Attribute = new LdapAttributeDescription(attribute.Span);
        }

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                Present = Attribute.GetBytes()
            };
        }

        public override string ToString()
        {
            return $"({Attribute}=*)";
        }
    }
}
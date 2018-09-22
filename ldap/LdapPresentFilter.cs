using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapPresentFilter : LdapFilter
    {
        public string Attribute { get; }

        internal LdapPresentFilter(ReadOnlyMemory<byte> attribute)
        {
            Attribute = Encoding.UTF8.GetString(attribute.Span);
        }

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                Present = Encoding.UTF8.GetBytes(Attribute)
            };
        }

        public override string ToString()
        {
            return $"({Attribute}=*)";
        }
    }
}
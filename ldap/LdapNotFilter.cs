using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapNotFilter : LdapFilter
    {
        public LdapFilter Filter { get; }

        internal LdapNotFilter(Asn1Filter filter)
        {
            Filter = Create(filter);
        }

        internal LdapNotFilter(LdapFilter filter)
        {
            if (filter is null)
                throw new ArgumentNullException(nameof(filter));

            Filter = filter;
        }

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                Not = Filter.GetAsn()
            };
        }

        public override string ToString()
        {
            return $"(!{Filter})";
        }
    }
}
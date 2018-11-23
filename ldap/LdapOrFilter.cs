using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapOrFilter : LdapFilter
    {
        public IReadOnlyList<LdapFilter> Filter { get; }

        internal LdapOrFilter(Asn1Filter[] filter)
        {
            var ldapFilter = new LdapFilter[filter.Length];
            for (int i = 0; i < filter.Length; i++)
            {
                ldapFilter[i] = LdapFilter.Create(filter[i]);
            }
            Filter = ldapFilter;
        }

        internal LdapOrFilter(LdapFilter[] inner)
        {
            if (inner is null)
                throw new ArgumentNullException(nameof(inner));
            
            Filter = inner;
        }

        internal override Asn1Filter GetAsn()
        {
            var filter = new Asn1Filter[Filter.Count];
            for (int i = 0; i < Filter.Count; i++)
            {
                filter[i] = Filter[i].GetAsn();
            }
            return new Asn1Filter
            {
                Or = filter
            };
        }

        public override string ToString()
        {
            return $"(|{String.Join(String.Empty, Filter)})";
        }
    }
}
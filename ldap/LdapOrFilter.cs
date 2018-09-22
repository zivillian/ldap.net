using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapOrFilter : LdapFilter
    {
        public LdapFilter[] Filter { get; }

        internal LdapOrFilter(Asn1Filter[] filter)
        {
            Filter = new LdapFilter[filter.Length];
            for (int i = 0; i < filter.Length; i++)
            {
                Filter[i] = LdapFilter.Create(filter[i]);
            }
        }

        internal override Asn1Filter GetAsn()
        {
            var filter = new Asn1Filter[Filter.Length];
            for (int i = 0; i < Filter.Length; i++)
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
            object[] objects = Filter;
            return $"(|{String.Join(String.Empty, objects)})";
        }
    }
}
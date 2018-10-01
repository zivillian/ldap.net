using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapFilter
    {
        internal static LdapFilter Create(Asn1Filter filter)
        {
            if (filter.And != null)
            {
                return new LdapAndFilter(filter.And);
            }
            else if (filter.Or != null)
            {
                return new LdapOrFilter(filter.Or);
            }
            else if (filter.Not != null)
            {
                return new LdapNotFilter(filter.Not);
            }
            else if (filter.EqualityMatch != null)
            {
                return new LdapEqualityFilter(filter.EqualityMatch);
            }
            else if (filter.Substrings != null)
            {
                return new LdapSubstringFilter(filter.Substrings);
            }
            else if (filter.GreaterOrEqual != null)
            {
                return new LdapGreaterOrEqualFilter(filter.GreaterOrEqual);
            }
            else if (filter.LessOrEqual != null)
            {
                return new LdapLessOrEqualFilter(filter.LessOrEqual);
            }
            else if (filter.Present.HasValue)
            {
                return new LdapPresentFilter(filter.Present.Value);
            }
            else if (filter.ApproxMatch != null)
            {
                return new LdapApproxMatchFilter(filter.ApproxMatch);
            }
            else if (filter.ExtensibleMatch != null)
            {
                return new LdapExtensibleMatchFilter(filter.ExtensibleMatch);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        internal abstract Asn1Filter GetAsn();

        public abstract override string ToString();
    }
}
namespace zivillian.ldap
{
    public abstract class LdapFilterVisitor
    {
        public virtual void Visit(LdapFilter filter)
        {
            if (filter is LdapAndFilter and)
            {
                VisitAnd(and);
            }
            else if (filter is LdapOrFilter or)
            {
                VisitOr(or);
            }
            else if (filter is LdapNotFilter not)
            {
                VisitNot(not);
            }
            else if (filter is LdapEqualityFilter equality)
            {
                VisitEquality(equality);
            }
            else if (filter is LdapSubstringFilter substring)
            {
                VisitSubstring(substring);
            }
            else if (filter is LdapGreaterOrEqualFilter greaterOrEqual)
            {
                VisitGreaterOrEqual(greaterOrEqual);
            }
            else if (filter is LdapLessOrEqualFilter lessOrEqual)
            {
                VisitLessOrEqual(lessOrEqual);
            }
            else if (filter is LdapPresentFilter present)
            {
                VisitPresent(present);
            }
            else if (filter is LdapApproxMatchFilter approxMatch)
            {
                VisitApproxMatch(approxMatch);
            }
            else if (filter is LdapExtensibleMatchFilter extensibleMatch)
            {
                VisitExtensibleMatch(extensibleMatch);
            }
        }

        protected virtual void VisitAnd(LdapAndFilter filter)
        {
            foreach (var ldapFilter in filter.Filter)
            {
                Visit(ldapFilter);
            }
        }

        protected virtual void VisitOr(LdapOrFilter filter)
        {
            foreach (var ldapFilter in filter.Filter)
            {
                Visit(ldapFilter);
            }
        }

        protected virtual void VisitNot(LdapNotFilter filter)
        {
            Visit(filter.Filter);
        }

        protected virtual void VisitEquality(LdapEqualityFilter filter)
        {
        }

        protected virtual void VisitSubstring(LdapSubstringFilter filter)
        {
        }

        protected virtual void VisitGreaterOrEqual(LdapGreaterOrEqualFilter filter)
        {
        }

        protected virtual void VisitLessOrEqual(LdapLessOrEqualFilter filter)
        {
        }

        protected virtual void VisitPresent(LdapPresentFilter filter)
        {
        }

        protected virtual void VisitApproxMatch(LdapApproxMatchFilter filter)
        {
        }

        protected virtual void VisitExtensibleMatch(LdapExtensibleMatchFilter filter)
        {
        }
    }
}
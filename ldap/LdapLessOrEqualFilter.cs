using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapLessOrEqualFilter : LdapCompareFilter
    {
        internal LdapLessOrEqualFilter(Asn1AttributeValueAssertion assertion)
            : base(assertion)
        {
        }

        internal LdapLessOrEqualFilter(LdapAttributeAssertion assertion)
            : base(assertion)
        {
        }

        protected override string CompareOperator { get; } = "<=";

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                LessOrEqual = GetAssertion()
            };
        }
    }
}
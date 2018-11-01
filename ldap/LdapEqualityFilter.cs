using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapEqualityFilter : LdapCompareFilter
    {
        internal LdapEqualityFilter(Asn1AttributeValueAssertion assertion)
            : base(assertion)
        {
        }

        internal LdapEqualityFilter(LdapAttributeAssertion assertion)
            : base(assertion)
        {
        }

        protected override string CompareOperator { get; } = "=";

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                EqualityMatch = GetAssertion()
            };
        }
    }
}
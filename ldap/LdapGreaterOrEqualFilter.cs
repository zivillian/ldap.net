using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapGreaterOrEqualFilter : LdapCompareFilter
    {
        internal LdapGreaterOrEqualFilter(Asn1AttributeValueAssertion assertion)
            : base(assertion)
        {
        }

        internal LdapGreaterOrEqualFilter(LdapAttributeAssertion assertion)
            : base(assertion)
        {
        }

        protected override string Operator { get; } = ">=";

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                GreaterOrEqual = GetAssertion()
            };
        }
    }
}
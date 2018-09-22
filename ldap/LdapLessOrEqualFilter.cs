using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapLessOrEqualFilter : LdapCompareFilter
    {
        internal LdapLessOrEqualFilter(Asn1AttributeValueAssertion assertion)
            : base(assertion)
        {
        }

        protected override string Operator { get; } = "<=";

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                LessOrEqual = GetAssertion()
            };
        }
    }
}
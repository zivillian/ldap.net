using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapApproxMatchFilter : LdapCompareFilter
    {
        internal LdapApproxMatchFilter(Asn1AttributeValueAssertion assertion)
            : base(assertion)
        {
        }

        internal LdapApproxMatchFilter(LdapAttributeAssertion assertion)
            : base(assertion)
        {
        }

        protected override string CompareOperator { get; } = "~=";

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                ApproxMatch = GetAssertion()
            };
        }
    }
}
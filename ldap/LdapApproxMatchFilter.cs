using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapApproxMatchFilter : LdapCompareFilter
    {
        internal LdapApproxMatchFilter(Asn1AttributeValueAssertion assertion)
            : base(assertion)
        {
        }

        protected override string Operator { get; } = "~=";

        internal override Asn1Filter GetAsn()
        {
            return new Asn1Filter
            {
                ApproxMatch = GetAssertion()
            };
        }
    }
}
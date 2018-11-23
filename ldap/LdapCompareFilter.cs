using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapCompareFilter : LdapFilter
    {
        public LdapAttributeAssertion Assertion { get; }

        protected abstract string CompareOperator { get; }

        internal LdapCompareFilter(Asn1AttributeValueAssertion assertion)
        {
            Assertion = new LdapAttributeAssertion(assertion);
        }

        internal LdapCompareFilter(LdapAttributeAssertion assertion)
        {
            Assertion = assertion;
        }

        internal Asn1AttributeValueAssertion GetAssertion()
        {
            return Assertion.GetAsn();
        }

        public override string ToString()
        {
            return $"({Assertion.Attribute}{CompareOperator}{Assertion.Value.Span.EscapeAssertionValue()})";
        }
    }
}
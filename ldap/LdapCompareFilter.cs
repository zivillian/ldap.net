using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapCompareFilter : LdapFilter
    {
        public LdapAttributeAssertion Assertion { get; }

        protected abstract string Operator { get; }

        internal LdapCompareFilter(Asn1AttributeValueAssertion assertion)
        {
            Assertion = new LdapAttributeAssertion(assertion);
        }

        internal Asn1AttributeValueAssertion GetAssertion()
        {
            return Assertion.GetAsn();
        }

        public override string ToString()
        {
            return $"({Assertion.Attribute}{Operator}{Assertion.Value})";
        }
    }
}
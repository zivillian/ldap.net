using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAttributeAssertion
    {
        public LdapAttributeDescription Attribute { get; }
        
        public ReadOnlyMemory<byte> Value { get; }

        internal LdapAttributeAssertion(Asn1AttributeValueAssertion assertion)
        {
            Attribute = new LdapAttributeDescription(assertion.Description.Span);
            Value = assertion.Value;
        }

        internal Asn1AttributeValueAssertion GetAsn()
        {
            return new Asn1AttributeValueAssertion
            {
                Description = Attribute.GetBytes(),
                Value = Value
            };
        }
    }
}
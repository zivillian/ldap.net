using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAttributeAssertion
    {
        public LdapAttributeDescription Attribute { get; }
        
        public string Value { get; }

        internal LdapAttributeAssertion(Asn1AttributeValueAssertion assertion)
        {
            Attribute = new LdapAttributeDescription(assertion.Description.Span);
            Value = LdapFilter.Unescape(Encoding.UTF8.GetString(assertion.Value.Span));
        }

        internal Asn1AttributeValueAssertion GetAsn()
        {
            return new Asn1AttributeValueAssertion
            {
                Description = Attribute.GetBytes(),
                Value = Encoding.UTF8.GetBytes(LdapFilter.Escape(Value))
            };
        }
    }
}
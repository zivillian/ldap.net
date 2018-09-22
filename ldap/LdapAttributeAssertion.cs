using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAttributeAssertion
    {
        public string Attribute { get; }
        
        public string Value { get; }

        internal LdapAttributeAssertion(Asn1AttributeValueAssertion assertion)
        {
            Attribute = Encoding.UTF8.GetString(assertion.Description.Span);
            Value = LdapFilter.Unescape(Encoding.UTF8.GetString(assertion.Value.Span));
        }

        internal Asn1AttributeValueAssertion GetAsn()
        {
            return new Asn1AttributeValueAssertion
            {
                Description = Encoding.UTF8.GetBytes(Attribute),
                Value = Encoding.UTF8.GetBytes(LdapFilter.Escape(Value))
            };
        }
    }
}
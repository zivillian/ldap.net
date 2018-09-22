using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapCompareFilter : LdapFilter
    {
        public string Attribute { get; }
        
        public string Value { get; }

        protected abstract string Operator { get; }

        internal LdapCompareFilter(Asn1AttributeValueAssertion assertion)
        {
            Attribute = Encoding.UTF8.GetString(assertion.Description.Span);
            Value = Unescape(Encoding.UTF8.GetString(assertion.Value.Span));
        }

        internal Asn1AttributeValueAssertion GetAssertion()
        {
            return new Asn1AttributeValueAssertion
            {
                Description = Encoding.UTF8.GetBytes(Attribute),
                Value = Encoding.UTF8.GetBytes(Escape(Value))
            };
        }

        public override string ToString()
        {
            return $"({Attribute}{Operator}{Value})";
        }
    }
}
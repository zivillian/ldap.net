using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtensibleMatchFilter : LdapFilter
    {
        public LdapAttributeDescription Attribute { get; }

        public bool IsDnAttribute { get; }

        public string MatchingRuleId { get; }

        public string Value { get; }

        internal LdapExtensibleMatchFilter(Asn1MatchingRuleAssertion assertion)
        {
            if (assertion.Type.HasValue)
                Attribute = new LdapAttributeDescription(assertion.Type.Value.Span);
            IsDnAttribute = assertion.DNAttributes;
            if (assertion.MatchingRule.HasValue)
                MatchingRuleId = assertion.MatchingRule.Value.Span.LdapString();
            Value = Unescape(Encoding.UTF8.GetString(assertion.Value.Span));
        }

        internal override Asn1Filter GetAsn()
        {
            var assertion = new Asn1MatchingRuleAssertion
            {
                DNAttributes = IsDnAttribute,
                Value = Encoding.UTF8.GetBytes(Escape(Value))
            };
            if (Attribute != null)
                assertion.Type = Attribute.GetBytes();
            if (MatchingRuleId != null)
                assertion.MatchingRule = MatchingRuleId.LdapString();
            return new Asn1Filter
            {
                ExtensibleMatch = assertion
            };
        }

        public override string ToString()
        {
            var result = new StringBuilder('(');
            if (Attribute != null)
                result.Append(Attribute);
            if (IsDnAttribute)
                result.Append(":dn");
            if (MatchingRuleId != null)
            {
                result.Append(':');
                result.Append(MatchingRuleId);
            }
            result.Append(":=");
            result.Append(')');
            return result.ToString();
        }
    }
}
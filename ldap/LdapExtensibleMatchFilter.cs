using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtensibleMatchFilter : LdapFilter
    {
        public string Attribute { get; }

        public bool IsDnAttribute { get; }

        public string MatchingRuleId { get; }

        public string Value { get; }

        internal LdapExtensibleMatchFilter(Asn1MatchingRuleAssertion assertion)
        {
            if (assertion.Type.HasValue)
                Attribute = Encoding.UTF8.GetString(assertion.Type.Value.Span);
            IsDnAttribute = assertion.DNAttributes;
            if (assertion.MatchingRule.HasValue)
                MatchingRuleId = Encoding.UTF8.GetString(assertion.MatchingRule.Value.Span);
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
                assertion.Type = Encoding.UTF8.GetBytes(Attribute);
            if (MatchingRuleId != null)
                assertion.MatchingRule = Encoding.UTF8.GetBytes(MatchingRuleId);
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
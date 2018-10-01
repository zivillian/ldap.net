using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapExtensibleMatchFilter : LdapFilter
    {
        public LdapAttributeDescription Attribute { get; }

        public bool IsDnAttribute { get; }

        public string MatchingRuleId { get; }

        public ReadOnlyMemory<byte> Value { get; }

        internal LdapExtensibleMatchFilter(Asn1MatchingRuleAssertion assertion)
        {
            if (assertion.Type.HasValue)
                Attribute = new LdapAttributeDescription(assertion.Type.Value.Span);
            IsDnAttribute = assertion.DNAttributes.GetValueOrDefault();
            if (assertion.MatchingRule.HasValue)
                //RFC 4511 4.1.8 && RFC 4520 3.4
                MatchingRuleId = assertion.MatchingRule.Value.Span.Oid();
            Value = assertion.Value;
        }

        internal override Asn1Filter GetAsn()
        {
            var assertion = new Asn1MatchingRuleAssertion
            {
                Value = Value
            };
            if (IsDnAttribute)
                assertion.DNAttributes = true;
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
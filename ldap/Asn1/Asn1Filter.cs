using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [Choice]
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1Filter
    {
        /*
         * Filter ::= CHOICE {
         *      and             [0] SET SIZE (1..MAX) OF filter Filter,
         *      or              [1] SET SIZE (1..MAX) OF filter Filter,
         *      not             [2] Filter,
         *      equalityMatch   [3] AttributeValueAssertion,
         *      substrings      [4] SubstringFilter,
         *      greaterOrEqual  [5] AttributeValueAssertion,
         *      lessOrEqual     [6] AttributeValueAssertion,
         *      present         [7] AttributeDescription,
         *      approxMatch     [8] AttributeValueAssertion,
         *      extensibleMatch [9] MatchingRuleAssertion,
         *      ...  }
         *
         * AttributeDescription ::= LDAPString -- Constrained to <attributedescription> -- [RFC4512]
         */
        [SetOf]
        [ExpectedTag(TagClass.ContextSpecific, 0)]
        public Asn1Filter[] And;

        [SetOf]
        [ExpectedTag(TagClass.ContextSpecific, 1)]
        public Asn1Filter[] Or;

        //TODO
        [ExpectedTag(TagClass.ContextSpecific, 2)]
        [AnyValue]
        public ReadOnlyMemory<byte>? Not;

        [ExpectedTag(TagClass.ContextSpecific, 3)]
        public Asn1AttributeValueAssertion? Equality;

        [ExpectedTag(TagClass.ContextSpecific, 4)]
        public Asn1SubstringFilter? Substring;

        [ExpectedTag(TagClass.ContextSpecific, 5)]
        public Asn1AttributeValueAssertion? GreaterOrEqual;

        [ExpectedTag(TagClass.ContextSpecific, 6)]
        public Asn1AttributeValueAssertion? LessOrEqual;

        [ExpectedTag(TagClass.ContextSpecific, 7)]
        [OctetString]
        public ReadOnlyMemory<byte>? Present;

        [ExpectedTag(TagClass.ContextSpecific, 8)]
        public Asn1AttributeValueAssertion? ApproxMatch;

        [ExpectedTag(TagClass.ContextSpecific, 9)]
        public Asn1MatchingRuleAssertion? ExtensibleMatch;
    }
}
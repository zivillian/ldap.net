using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1MatchingRuleAssertion
    {
        /*
         * MatchingRuleAssertion ::= SEQUENCE {
         *      matchingRule    [1] MatchingRuleId OPTIONAL,
         *      type            [2] AttributeDescription OPTIONAL,
         *      matchValue      [3] AssertionValue,
         *      dnAttributes    [4] BOOLEAN DEFAULT FALSE }
         *
         * MatchingRuleId ::= LDAPString
         *
         * AssertionValue ::= OCTET STRING
         */
        [OctetString]
        public ReadOnlyMemory<byte> MatchingRule;

        [OctetString]
        public ReadOnlyMemory<byte> Type;

        [OctetString]
        public ReadOnlyMemory<byte> Value;

        [DefaultValue(0x01, 0x01, 0x00)]
        public bool DNAttributes;
    }
}
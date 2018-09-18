using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1AttributeValueAssertion
    {
        /*
         * AttributeValueAssertion ::= SEQUENCE {
         *      attributeDesc   AttributeDescription,
         *      assertionValue  AssertionValue }
         *
         * AttributeDescription ::= LDAPString
         *           -- Constrained to <attributedescription>
         *           -- [RFC4512]
         *
         * AssertionValue ::= OCTET STRING
         */
        [OctetString]
        public ReadOnlyMemory<byte> Description;

        [OctetString]
        public ReadOnlyMemory<byte> Value;
    }
}
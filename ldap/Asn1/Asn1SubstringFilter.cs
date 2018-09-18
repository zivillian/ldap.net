using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1SubstringFilter
    {
        /*
         * SubstringFilter ::= SEQUENCE {
         *      type           AttributeDescription,
         *      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
         *           initial [0] AssertionValue,  -- can occur at most once
         *           any     [1] AssertionValue,
         *           final   [2] AssertionValue } -- can occur at most once
         *      }
         */
        [OctetString]
        public ReadOnlyMemory<byte> Type;

        [SequenceOf]
        public Asn1Substring[] Substrings;
    }
}
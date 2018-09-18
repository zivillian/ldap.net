using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1SaslCredentials
    {
        /*
         * SaslCredentials ::= SEQUENCE {
         *      mechanism               LDAPString,
         *      credentials             OCTET STRING OPTIONAL }
         */
        [OctetString]
        public ReadOnlyMemory<byte> Mechanism;

        [OctetString, OptionalValue]
        public ReadOnlyMemory<byte> Credentials;
    }
}
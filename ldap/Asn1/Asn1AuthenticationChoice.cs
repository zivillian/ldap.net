using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [Choice]
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1AuthenticationChoice
    {
        /*
         * AuthenticationChoice ::= CHOICE {
         *      simple                  [0] OCTET STRING,
         *                -- 1 and 2 reserved
         *      sasl                    [3] SaslCredentials,
         *      ...  }
         */
        [OctetString]
        [ExpectedTag(TagClass.ContextSpecific, 0)]
        public ReadOnlyMemory<byte>? Simple;

        [ExpectedTag(TagClass.ContextSpecific, 3)]
        public Asn1SaslCredentials? Sasl;
    }
}
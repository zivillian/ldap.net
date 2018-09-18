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

        [AnyValue]
        [ExpectedTag(TagClass.ContextSpecific, 1)]
        public ReadOnlyMemory<byte>? Reserved;
        
        [AnyValue]
        [ExpectedTag(TagClass.ContextSpecific, 2)]
        public ReadOnlyMemory<byte>? Reserved2;
        
        [ExpectedTag(TagClass.ContextSpecific, 3)]
        public Asn1SaslCredentials? Sasl;
    }
}
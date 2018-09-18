using System;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [Choice]
    internal struct Asn1Substring
    {
        [ExpectedTag(TagClass.ContextSpecific, 0)]
        [OctetString]
        public ReadOnlyMemory<byte> Initial;

        [ExpectedTag(TagClass.ContextSpecific, 1)]
        [OctetString]
        public ReadOnlyMemory<byte> Any;

        [ExpectedTag(TagClass.ContextSpecific, 2)]
        [OctetString]
        public ReadOnlyMemory<byte> Final;
    }
}
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1SearchResultEntry
    {
        /*
         * SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
         *      objectName      LDAPDN,
         *      attributes      PartialAttributeList }
         *
         * PartialAttributeList ::= SEQUENCE OF
         *        partialAttribute PartialAttribute
         */
        [OctetString]
        public ReadOnlyMemory<byte> ObjectName;

        [SequenceOf]
        public Asn1PartialAttribute[] Attributes;
    }
}
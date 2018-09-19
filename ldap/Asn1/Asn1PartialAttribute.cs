using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1PartialAttribute
    {
        /*
         * PartialAttribute ::= SEQUENCE {
         *      type       AttributeDescription,
         *      vals       SET OF value AttributeValue }
         *
         * AttributeDescription ::= LDAPString
         *            -- Constrained to 
         *            -- [RFC4512]
         *
         * AttributeValue ::= OCTET STRING
         */

        [OctetString]
        public ReadOnlyMemory<byte> Type;
        
        //TODO
        [AnyValue]
        public ReadOnlyMemory<byte> Attributes;
    }
}
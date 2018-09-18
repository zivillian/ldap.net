using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1Control
    {
        /*
         * Control ::= SEQUENCE {
         *      controlType             LDAPOID,
         *      criticality             BOOLEAN DEFAULT FALSE,
         *      controlValue            OCTET STRING OPTIONAL }
         *
         * LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
         */

        [OctetString]
        public ReadOnlyMemory<byte> ControlType;

        [DefaultValue(0x01, 0x01, 0x00)]
        public bool Criticality;

        [OctetString]
        [OptionalValue]
        public ReadOnlyMemory<byte>? ControlValue;
    }
}
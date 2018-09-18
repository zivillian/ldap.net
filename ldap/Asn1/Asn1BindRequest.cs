using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1BindRequest
    {
        /*
         * BindRequest ::= [APPLICATION 0] SEQUENCE {
         *      version                 INTEGER (1 ..  127),
         *      name                    LDAPDN,
         *      authentication          AuthenticationChoice }
         *
         */
        public byte Version;

        [OctetString]
        public ReadOnlyMemory<byte> Name;

        public Asn1AuthenticationChoice Authentication;
    }
}
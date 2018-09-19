using System;
using System.Collections.Generic;
using System.Security.Cryptography.Asn1;
using System.Text;

namespace zivillian.ldap.Asn1.Generated
{
    public static class Asn1Serializer
    {
        public static void Deserialize(byte[] data)
        {
            Asn1LdapMessage.Decode(data, AsnEncodingRules.BER);
        }
    }
}

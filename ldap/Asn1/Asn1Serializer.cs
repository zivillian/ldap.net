using System;
using System.Collections.Generic;
using System.Security.Cryptography.Asn1;
using System.Text;

namespace zivillian.ldap.Asn1
{
    public static class Asn1Serializer
    {
        internal static Asn1LdapMessage Deserialize(ReadOnlyMemory<byte> data)
        {
            return Asn1LdapMessage.Decode(data, AsnEncodingRules.BER);
        }

        internal static byte[] Serialize(Asn1LdapMessage message)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.BER))
            {
                message.Encode(writer);
                return writer.Encode();
            }
        }
    }
}

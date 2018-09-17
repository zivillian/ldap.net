using System;
using System.Security.Cryptography.Asn1;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapReader
    {
        public static LdapRequestMessage ReadMessage(ReadOnlyMemory<byte> source)
        {
            var message = AsnSerializer.Deserialize<Asn1LdapMessage>(source, AsnEncodingRules.BER);
            return LdapRequestMessage.Create(message);
        }
    }
}

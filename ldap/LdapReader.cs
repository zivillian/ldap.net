using System;
using System.Security.Cryptography.Asn1;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapReader
    {
        public static LdapRequestMessage ReadMessage(ReadOnlyMemory<byte> source)
        {
            var message = Asn1Serializer.Deserialize(source);
            return LdapRequestMessage.Create(message);
        }
    }
}

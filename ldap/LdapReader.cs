using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public static class LdapReader
    {
        public static LdapRequestMessage ReadMessage(ReadOnlyMemory<byte> source)
        {
            var message = Asn1Serializer.Deserialize(source);
            return LdapRequestMessage.Create(message);
        }

        public static byte[] WriteMessage(LdapRequestMessage message)
        {
            return Asn1Serializer.Serialize(message.GetAsn());
        }
    }
}

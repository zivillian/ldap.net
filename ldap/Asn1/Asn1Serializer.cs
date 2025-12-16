using System;
using System.Formats.Asn1;

namespace zivillian.ldap.Asn1
{
    public static class Asn1Serializer
    {
        internal static Asn1LdapMessage Deserialize(ReadOnlyMemory<byte> data)
        {
            try
            {
                return Asn1LdapMessage.Decode(data, AsnEncodingRules.BER);
            }
            catch (Exception ex) when (ex is AsnContentException || ex is CryptographicException)
            {
                throw new LdapProtocolException("invalid BER encoding", ex);
            }
        }

        internal static byte[] Serialize(Asn1LdapMessage message)
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);
            message.Encode(writer);
            return writer.Encode();
        }
    }
}

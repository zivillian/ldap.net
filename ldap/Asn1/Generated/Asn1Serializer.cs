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

        public static void DeserializeDeleteRequest(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data.Slice(9), AsnEncodingRules.BER);
            reader.ReadOctetString(new Asn1Tag(TagClass.Application, 10));
            reader.ThrowIfNotEmpty();
        }

        public static void DeserializeBindRequest(ReadOnlyMemory<byte> data)
        {
            Asn1BindRequest.Decode(new Asn1Tag(TagClass.Application, 0), data.Slice(9), AsnEncodingRules.BER);
        }

        public static void DeserializeUnbindRequest(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data.Slice(9), AsnEncodingRules.BER);
            reader.ReadNull(new Asn1Tag(TagClass.Application, 2));
            reader.ThrowIfNotEmpty();
        }

        public static void DeserializeBindResponse(ReadOnlyMemory<byte> data)
        {
            Asn1BindResponse.Decode(new Asn1Tag(TagClass.Application, 1), data.Slice(5), AsnEncodingRules.BER);
        }

        public static void DeserializeSearchRequest(ReadOnlyMemory<byte> data)
        {
            Asn1SearchRequest.Decode(new Asn1Tag(TagClass.Application, 3), data.Slice(9), AsnEncodingRules.BER);
        }

        public static void DeserializeSearchRequestPartial(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data.Slice(9), AsnEncodingRules.BER);
            Asn1SearchRequest.Decode(reader, new Asn1Tag(TagClass.Application, 3), out _);
        }

        public static void DeserializeSearchResEntry(ReadOnlyMemory<byte> data)
        {
            Asn1SearchResultEntry.Decode(new Asn1Tag(TagClass.Application, 4), data.Slice(7), AsnEncodingRules.BER);
        }
    }
}

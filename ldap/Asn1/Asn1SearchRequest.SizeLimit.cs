using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace zivillian.ldap.Asn1
{
    internal partial class Asn1SearchRequest
    {
        internal int SizeLimit
        {
            get
            {
                return DecodeSizeLimit();
            }
            set
            {
                var writer = new AsnWriter(AsnEncodingRules.BER);
                writer.WriteInteger(value);
                SizeLimitRaw = writer.Encode();
            }
        }

        internal int DecodeSizeLimit()
        {
            //snom is encoding the integer with two byte
            //which is not conform to T-REC-X.690-201508 sec 8.3.2
            //AsnDecoder is throwing an AsnContentException
            //thus we decode the value without manually
            var source = SizeLimitRaw.Span;
            var tag = Asn1Tag.Decode(source, out var tagLength);
            if (!tag.HasSameClassAndValue(Asn1Tag.Integer)) throw new LdapException();
            var length = AsnDecoder.DecodeLength(source.Slice(tagLength), AsnEncodingRules.BER, out var lengthLength);
            if (length is null) throw new LdapException("invalid BER encoding");
            var contents = source.Slice(tagLength + lengthLength, length.Value);
            if (contents.IsEmpty)
            {
                throw new AsnContentException();
            }
            bool isNegative = (contents[0] & 0x80) != 0;
            int accum = isNegative ? -1 : 0;

            for (int i = 0; i < contents.Length; i++)
            {
                accum <<= 8;
                accum |= contents[i];
            }

            return accum;
        }
    }
}

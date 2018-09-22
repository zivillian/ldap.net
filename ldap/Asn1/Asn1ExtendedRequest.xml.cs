using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1ExtendedRequest
    {
        internal ReadOnlyMemory<byte> Name;
        internal ReadOnlyMemory<byte>? Value;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), Name.Span);

            if (Value.HasValue)
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 1), Value.Value.Span);
            }

            writer.PopSequence(tag);
        }

        internal static Asn1ExtendedRequest Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1ExtendedRequest Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1ExtendedRequest decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1ExtendedRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1ExtendedRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1ExtendedRequest();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpName))
            {
                decoded.Name = tmpName;
            }
            else
            {
                decoded.Name = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 1), out ReadOnlyMemory<byte> tmpValue))
                {
                    decoded.Value = tmpValue;
                }
                else
                {
                    decoded.Value = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 1));
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1Control
    {
        internal ReadOnlyMemory<byte> Type;
        internal bool Criticality;
        internal ReadOnlyMemory<byte>? Value;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(Type.Span);
            writer.WriteBoolean(Criticality);

            if (Value.HasValue)
            {
                writer.WriteOctetString(Value.Value.Span);
            }

            writer.PopSequence(tag);
        }

        internal static Asn1Control Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1Control Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1Control decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1Control decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1Control decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1Control();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpType))
            {
                decoded.Type = tmpType;
            }
            else
            {
                decoded.Type = sequenceReader.ReadOctetString();
            }

            decoded.Criticality = sequenceReader.ReadBoolean();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpValue))
                {
                    decoded.Value = tmpValue;
                }
                else
                {
                    decoded.Value = sequenceReader.ReadOctetString();
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

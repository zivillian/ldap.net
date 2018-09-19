using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1.Generated
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1AttributeValueAssertion
    {
        internal ReadOnlyMemory<byte> Description;
        internal ReadOnlyMemory<byte> Value;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(Description.Span);
            writer.WriteOctetString(Value.Span);
            writer.PopSequence(tag);
        }

        internal static Asn1AttributeValueAssertion Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1AttributeValueAssertion Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1AttributeValueAssertion decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1AttributeValueAssertion decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1AttributeValueAssertion decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpDescription))
            {
                decoded.Description = tmpDescription;
            }
            else
            {
                decoded.Description = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpValue))
            {
                decoded.Value = tmpValue;
            }
            else
            {
                decoded.Value = sequenceReader.ReadOctetString();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

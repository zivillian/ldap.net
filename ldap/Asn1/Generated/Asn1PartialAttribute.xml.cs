using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1.Generated
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1PartialAttribute
    {
        internal ReadOnlyMemory<byte> Type;
        internal ReadOnlyMemory<byte>[] Values;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(Type.Span);

            writer.PushSetOf();
            for (int i = 0; i < Values.Length; i++)
            {
                writer.WriteOctetString(Values[i].Span); 
            }
            writer.PopSetOf();

            writer.PopSequence(tag);
        }

        internal static Asn1PartialAttribute Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1PartialAttribute Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1PartialAttribute decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1PartialAttribute decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1PartialAttribute decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpType))
            {
                decoded.Type = tmpType;
            }
            else
            {
                decoded.Type = sequenceReader.ReadOctetString();
            }


            // Decode SEQUENCE OF for Values
            {
                collectionReader = sequenceReader.ReadSetOf();
                var tmpList = new List<ReadOnlyMemory<byte>>();
                ReadOnlyMemory<byte> tmpItem;

                while (collectionReader.HasData)
                {

                    if (collectionReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmp))
                    {
                        tmpItem = tmp;
                    }
                    else
                    {
                        tmpItem = collectionReader.ReadOctetString();
                    }
 
                    tmpList.Add(tmpItem);
                }

                decoded.Values = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

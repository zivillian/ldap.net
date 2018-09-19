using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1.Generated
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1SubstringFilter
    {
        internal ReadOnlyMemory<byte> Type;
        internal Asn1Substring[] Substrings;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(Type.Span);

            writer.PushSequence();
            for (int i = 0; i < Substrings.Length; i++)
            {
                Substrings[i].Encode(writer); 
            }
            writer.PopSequence();

            writer.PopSequence(tag);
        }

        internal static Asn1SubstringFilter Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1SubstringFilter Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1SubstringFilter decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1SubstringFilter decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1SubstringFilter decoded)
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


            // Decode SEQUENCE OF for Substrings
            {
                collectionReader = sequenceReader.ReadSequence();
                var tmpList = new List<Asn1Substring>();
                Asn1Substring tmpItem;

                while (collectionReader.HasData)
                {
                    Asn1Substring.Decode(collectionReader, out tmpItem); 
                    tmpList.Add(tmpItem);
                }

                decoded.Substrings = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

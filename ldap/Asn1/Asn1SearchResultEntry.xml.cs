using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SearchResultEntry
    {
        internal ReadOnlyMemory<byte> ObjectName;
        internal Asn1PartialAttribute[] Attributes;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(ObjectName.Span);

            writer.PushSequence();
            for (int i = 0; i < Attributes.Length; i++)
            {
                Attributes[i].Encode(writer); 
            }
            writer.PopSequence();

            writer.PopSequence(tag);
        }

        internal static Asn1SearchResultEntry Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1SearchResultEntry Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1SearchResultEntry decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1SearchResultEntry decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1SearchResultEntry decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1SearchResultEntry();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpObjectName))
            {
                decoded.ObjectName = tmpObjectName;
            }
            else
            {
                decoded.ObjectName = sequenceReader.ReadOctetString();
            }


            // Decode SEQUENCE OF for Attributes
            {
                collectionReader = sequenceReader.ReadSequence();
                var tmpList = new List<Asn1PartialAttribute>();
                Asn1PartialAttribute tmpItem;

                while (collectionReader.HasData)
                {
                    Asn1PartialAttribute.Decode(collectionReader, out tmpItem); 
                    tmpList.Add(tmpItem);
                }

                decoded.Attributes = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

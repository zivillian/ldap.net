using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1SearchRequest
    {
        internal ReadOnlyMemory<byte> BaseObject;
        internal SearchScope Scope;
        internal DerefAliases DerefAliases;
        internal int SizeLimit;
        internal int TimeLimit;
        internal bool TypesOnly;
        internal Asn1Filter Filter;
        internal ReadOnlyMemory<byte>[] Attributes;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(BaseObject.Span);
            writer.WriteEnumeratedValue(Scope);
            writer.WriteEnumeratedValue(DerefAliases);
            writer.WriteInteger(SizeLimit);
            writer.WriteInteger(TimeLimit);
            writer.WriteBoolean(TypesOnly);
            Filter.Encode(writer);

            writer.PushSequence();
            for (int i = 0; i < Attributes.Length; i++)
            {
                writer.WriteOctetString(Attributes[i].Span); 
            }
            writer.PopSequence();

            writer.PopSequence(tag);
        }

        internal static Asn1SearchRequest Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1SearchRequest Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1SearchRequest decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1SearchRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1SearchRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpBaseObject))
            {
                decoded.BaseObject = tmpBaseObject;
            }
            else
            {
                decoded.BaseObject = sequenceReader.ReadOctetString();
            }

            decoded.Scope = sequenceReader.GetEnumeratedValue<SearchScope>();
            decoded.DerefAliases = sequenceReader.GetEnumeratedValue<DerefAliases>();

            if (!sequenceReader.TryReadInt32(out decoded.SizeLimit))
            {
                sequenceReader.ThrowIfNotEmpty();
            }


            if (!sequenceReader.TryReadInt32(out decoded.TimeLimit))
            {
                sequenceReader.ThrowIfNotEmpty();
            }

            decoded.TypesOnly = sequenceReader.ReadBoolean();
            Asn1Filter.Decode(sequenceReader, out decoded.Filter);

            // Decode SEQUENCE OF for Attributes
            {
                collectionReader = sequenceReader.ReadSequence();
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

                decoded.Attributes = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1PartialAttribute
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

            DecodeCore(reader, expectedTag, encoded, out Asn1PartialAttribute decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1PartialAttribute decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1PartialAttribute decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1PartialAttribute decoded)
        {
            decoded = new Asn1PartialAttribute();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.Type = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
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

                    if (collectionReader.TryReadPrimitiveOctetString(out tmpSpan))
                    {
                        tmpItem = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
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

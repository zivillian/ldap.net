// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SubstringFilter
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

            DecodeCore(reader, expectedTag, encoded, out Asn1SubstringFilter decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1SubstringFilter decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1SubstringFilter decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1SubstringFilter decoded)
        {
            decoded = new Asn1SubstringFilter();
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


            // Decode SEQUENCE OF for Substrings
            {
                collectionReader = sequenceReader.ReadSequence();
                var tmpList = new List<Asn1Substring>();
                Asn1Substring tmpItem;

                while (collectionReader.HasData)
                {
                    Asn1Substring.Decode(collectionReader, rebind, out tmpItem);
                    tmpList.Add(tmpItem);
                }

                decoded.Substrings = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

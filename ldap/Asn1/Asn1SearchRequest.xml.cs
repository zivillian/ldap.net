// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SearchRequest
    {
        internal ReadOnlyMemory<byte> BaseObject;
        internal SearchScope Scope;
        internal DerefAliases DerefAliases;
        internal int SizeLimit;
        internal int TimeLimit;
        internal bool TypesOnly;
        internal Asn1Filter Filter;
        internal ReadOnlyMemory<byte>[] Attributes = [];

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

            DecodeCore(reader, expectedTag, encoded, out Asn1SearchRequest decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1SearchRequest decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1SearchRequest decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1SearchRequest decoded)
        {
            decoded = new Asn1SearchRequest();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.BaseObject = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.BaseObject = sequenceReader.ReadOctetString();
            }

            decoded.Scope = sequenceReader.ReadEnumeratedValue<SearchScope>();
            decoded.DerefAliases = sequenceReader.ReadEnumeratedValue<DerefAliases>();

            if (!sequenceReader.TryReadInt32(out decoded.SizeLimit))
            {
                sequenceReader.ThrowIfNotEmpty();
            }


            if (!sequenceReader.TryReadInt32(out decoded.TimeLimit))
            {
                sequenceReader.ThrowIfNotEmpty();
            }

            decoded.TypesOnly = sequenceReader.ReadBoolean();
            Asn1Filter.Decode(sequenceReader, rebind, out decoded.Filter);

            // Decode SEQUENCE OF for Attributes
            {
                collectionReader = sequenceReader.ReadSequence();
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

                decoded.Attributes = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

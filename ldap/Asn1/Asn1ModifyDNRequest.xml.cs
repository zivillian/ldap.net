// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1ModifyDNRequest
    {
        internal ReadOnlyMemory<byte> Entry;
        internal ReadOnlyMemory<byte> NewRDN;
        internal bool DeleteOldRDN;
        internal ReadOnlyMemory<byte>? NewSuperior;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            writer.WriteOctetString(Entry.Span);
            writer.WriteOctetString(NewRDN.Span);
            writer.WriteBoolean(DeleteOldRDN);

            if (NewSuperior.HasValue)
            {
                writer.WriteOctetString(NewSuperior.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 0));
            }

            writer.PopSequence(tag);
        }

        internal static Asn1ModifyDNRequest Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static Asn1ModifyDNRequest Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, expectedTag, encoded, out Asn1ModifyDNRequest decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1ModifyDNRequest decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1ModifyDNRequest decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1ModifyDNRequest decoded)
        {
            decoded = new Asn1ModifyDNRequest();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.Entry = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.Entry = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.NewRDN = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.NewRDN = sequenceReader.ReadOctetString();
            }

            decoded.DeleteOldRDN = sequenceReader.ReadBoolean();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    decoded.NewSuperior = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.NewSuperior = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1Control
    {
        internal ReadOnlyMemory<byte> Type;
        internal bool? Criticality;
        internal ReadOnlyMemory<byte>? Value;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            writer.WriteOctetString(Type.Span);

            if (Criticality.HasValue)
            {
                writer.WriteBoolean(Criticality.Value);
            }


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

            DecodeCore(reader, expectedTag, encoded, out Asn1Control decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1Control decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1Control decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1Control decoded)
        {
            decoded = new Asn1Control();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
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


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
            {
                decoded.Criticality = sequenceReader.ReadBoolean();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
                {
                    decoded.Value = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
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

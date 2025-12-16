// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1MatchingRuleAssertion
    {
        internal ReadOnlyMemory<byte>? MatchingRule;
        internal ReadOnlyMemory<byte>? Type;
        internal ReadOnlyMemory<byte> Value;
        internal bool? DNAttributes;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);


            if (MatchingRule.HasValue)
            {
                writer.WriteOctetString(MatchingRule.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 1));
            }


            if (Type.HasValue)
            {
                writer.WriteOctetString(Type.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            writer.WriteOctetString(Value.Span, new Asn1Tag(TagClass.ContextSpecific, 3));

            if (DNAttributes.HasValue)
            {
                writer.WriteBoolean(DNAttributes.Value, new Asn1Tag(TagClass.ContextSpecific, 4));
            }

            writer.PopSequence(tag);
        }

        internal static Asn1MatchingRuleAssertion Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static Asn1MatchingRuleAssertion Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, expectedTag, encoded, out Asn1MatchingRuleAssertion decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1MatchingRuleAssertion decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1MatchingRuleAssertion decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1MatchingRuleAssertion decoded)
        {
            decoded = new Asn1MatchingRuleAssertion();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    decoded.MatchingRule = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.MatchingRule = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 1));
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    decoded.Type = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Type = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 2));
                }

            }


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                decoded.Value = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.Value = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 3));
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                decoded.DNAttributes = sequenceReader.ReadBoolean(new Asn1Tag(TagClass.ContextSpecific, 4));
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

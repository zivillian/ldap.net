// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1ExtendedResponse
    {
        internal ResultCode ResultCode;
        internal ReadOnlyMemory<byte> MatchedDN;
        internal ReadOnlyMemory<byte> DiagnosticMessage;
        internal ReadOnlyMemory<byte>[]? Referral;
        internal ReadOnlyMemory<byte>? Name;
        internal ReadOnlyMemory<byte>? Value;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            writer.WriteEnumeratedValue(ResultCode);
            writer.WriteOctetString(MatchedDN.Span);
            writer.WriteOctetString(DiagnosticMessage.Span);

            if (Referral != null)
            {

                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                for (int i = 0; i < Referral.Length; i++)
                {
                    writer.WriteOctetString(Referral[i].Span);
                }
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            }


            if (Name.HasValue)
            {
                writer.WriteOctetString(Name.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 10));
            }


            if (Value.HasValue)
            {
                writer.WriteOctetString(Value.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 11));
            }

            writer.PopSequence(tag);
        }

        internal static Asn1ExtendedResponse Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static Asn1ExtendedResponse Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, expectedTag, encoded, out Asn1ExtendedResponse decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1ExtendedResponse decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1ExtendedResponse decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1ExtendedResponse decoded)
        {
            decoded = new Asn1ExtendedResponse();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;

            decoded.ResultCode = sequenceReader.ReadEnumeratedValue<ResultCode>();

            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.MatchedDN = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.MatchedDN = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.DiagnosticMessage = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.DiagnosticMessage = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {

                // Decode SEQUENCE OF for Referral
                {
                    collectionReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
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

                    decoded.Referral = tmpList.ToArray();
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 10)))
                {
                    decoded.Name = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Name = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 10));
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 11)))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 11)))
                {
                    decoded.Value = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Value = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 11));
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

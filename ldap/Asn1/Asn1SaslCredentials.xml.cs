// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SaslCredentials
    {
        internal ReadOnlyMemory<byte> Mechanism;
        internal ReadOnlyMemory<byte>? Credentials;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            writer.WriteOctetString(Mechanism.Span);

            if (Credentials.HasValue)
            {
                writer.WriteOctetString(Credentials.Value.Span);
            }

            writer.PopSequence(tag);
        }

        internal static Asn1SaslCredentials Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static Asn1SaslCredentials Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, expectedTag, encoded, out Asn1SaslCredentials decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1SaslCredentials decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1SaslCredentials decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1SaslCredentials decoded)
        {
            decoded = new Asn1SaslCredentials();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;


            if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            {
                decoded.Mechanism = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }
            else
            {
                decoded.Mechanism = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
            {

                if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
                {
                    decoded.Credentials = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Credentials = sequenceReader.ReadOctetString();
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

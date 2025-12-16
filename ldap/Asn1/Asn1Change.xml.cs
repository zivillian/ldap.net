// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1Change
    {
        internal ChangeOperation Operation;
        internal Asn1PartialAttribute Modification;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            writer.WriteEnumeratedValue(Operation);
            Modification.Encode(writer);
            writer.PopSequence(tag);
        }

        internal static Asn1Change Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static Asn1Change Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, expectedTag, encoded, out Asn1Change decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1Change decoded)
        {
            Decode(reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1Change decoded)
        {
            DecodeCore(reader, expectedTag, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out Asn1Change decoded)
        {
            decoded = new Asn1Change();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);

            decoded.Operation = sequenceReader.ReadEnumeratedValue<ChangeOperation>();
            Asn1PartialAttribute.Decode(sequenceReader, rebind, out decoded.Modification);

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

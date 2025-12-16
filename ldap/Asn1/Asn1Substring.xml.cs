// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1Substring
    {
        internal ReadOnlyMemory<byte>? Initial;
        internal ReadOnlyMemory<byte>? Any;
        internal ReadOnlyMemory<byte>? Final;

#if DEBUG
        static Asn1Substring()
        {
            var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();
            Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>
            {
                if (usedTags.TryGetValue(tag, out string? existing))
                {
                    throw new InvalidOperationException($"Tag '{tag}' is in use by both '{existing}' and '{fieldName}'");
                }

                usedTags.Add(tag, fieldName);
            };

            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 0), "Initial");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 1), "Any");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 2), "Final");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false;

            if (Initial.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();

                writer.WriteOctetString(Initial.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 0));
                wroteValue = true;
            }

            if (Any.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();

                writer.WriteOctetString(Any.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 1));
                wroteValue = true;
            }

            if (Final.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();

                writer.WriteOctetString(Final.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 2));
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }

        internal static Asn1Substring Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, encoded, out Asn1Substring decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1Substring decoded)
        {
            DecodeCore(reader, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1Substring decoded)
        {
            decoded = new Asn1Substring();
            Asn1Tag tag = reader.PeekTag();
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;

            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (reader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    decoded.Initial = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Initial = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                if (reader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    decoded.Any = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Any = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 1));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {

                if (reader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    decoded.Final = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Final = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 2));
                }

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

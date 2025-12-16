// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1AuthenticationChoice
    {
        internal ReadOnlyMemory<byte>? Simple;
        internal Asn1SaslCredentials? Sasl;

#if DEBUG
        static Asn1AuthenticationChoice()
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

            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 0), "Simple");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 3), "Sasl");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false;

            if (Simple.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();

                writer.WriteOctetString(Simple.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 0));
                wroteValue = true;
            }

            if (Sasl != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                Sasl.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 3));
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }

        internal static Asn1AuthenticationChoice Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, encoded, out Asn1AuthenticationChoice decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1AuthenticationChoice decoded)
        {
            DecodeCore(reader, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1AuthenticationChoice decoded)
        {
            decoded = new Asn1AuthenticationChoice();
            Asn1Tag tag = reader.PeekTag();
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;

            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (reader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    decoded.Simple = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Simple = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                Asn1SaslCredentials tmpSasl;
                Asn1SaslCredentials.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 3), rebind, out tmpSasl);
                decoded.Sasl = tmpSasl;

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

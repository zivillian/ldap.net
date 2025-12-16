// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1Filter
    {
        internal Asn1Filter[]? And;
        internal Asn1Filter[]? Or;
        internal Asn1Filter? Not;
        internal Asn1AttributeValueAssertion? EqualityMatch;
        internal Asn1SubstringFilter? Substrings;
        internal Asn1AttributeValueAssertion? GreaterOrEqual;
        internal Asn1AttributeValueAssertion? LessOrEqual;
        internal ReadOnlyMemory<byte>? Present;
        internal Asn1AttributeValueAssertion? ApproxMatch;
        internal Asn1MatchingRuleAssertion? ExtensibleMatch;

#if DEBUG
        static Asn1Filter()
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

            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 0), "And");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 1), "Or");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 2), "Not");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 3), "EqualityMatch");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 4), "Substrings");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 5), "GreaterOrEqual");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 6), "LessOrEqual");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 7), "Present");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 8), "ApproxMatch");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 9), "ExtensibleMatch");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false;

            if (And != null)
            {
                if (wroteValue)
                    throw new CryptographicException();


                writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
                for (int i = 0; i < And.Length; i++)
                {
                    And[i].Encode(writer);
                }
                writer.PopSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));

                wroteValue = true;
            }

            if (Or != null)
            {
                if (wroteValue)
                    throw new CryptographicException();


                writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));
                for (int i = 0; i < Or.Length; i++)
                {
                    Or[i].Encode(writer);
                }
                writer.PopSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));

                wroteValue = true;
            }

            if (Not != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                Not.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                wroteValue = true;
            }

            if (EqualityMatch != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                EqualityMatch.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 3));
                wroteValue = true;
            }

            if (Substrings != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                Substrings.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 4));
                wroteValue = true;
            }

            if (GreaterOrEqual != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                GreaterOrEqual.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 5));
                wroteValue = true;
            }

            if (LessOrEqual != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                LessOrEqual.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 6));
                wroteValue = true;
            }

            if (Present.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();

                writer.WriteOctetString(Present.Value.Span, new Asn1Tag(TagClass.ContextSpecific, 7));
                wroteValue = true;
            }

            if (ApproxMatch != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                ApproxMatch.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 8));
                wroteValue = true;
            }

            if (ExtensibleMatch != null)
            {
                if (wroteValue)
                    throw new CryptographicException();

                ExtensibleMatch.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 9));
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }

        internal static Asn1Filter Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);

            DecodeCore(reader, encoded, out Asn1Filter decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1Filter decoded)
        {
            DecodeCore(reader, rebind, out decoded);
        }

        private static void DecodeCore(AsnReader reader, ReadOnlyMemory<byte> rebind, out Asn1Filter decoded)
        {
            decoded = new Asn1Filter();
            Asn1Tag tag = reader.PeekTag();
            AsnReader explicitReader;
            AsnReader collectionReader;
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlyMemory<byte> tmpSpan;

            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                // Decode SEQUENCE OF for And
                {
                    collectionReader = reader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
                    var tmpList = new List<Asn1Filter>();
                    Asn1Filter tmpItem;

                    while (collectionReader.HasData)
                    {
                        Asn1Filter.Decode(collectionReader, rebind, out tmpItem);
                        tmpList.Add(tmpItem);
                    }

                    decoded.And = tmpList.ToArray();
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                // Decode SEQUENCE OF for Or
                {
                    collectionReader = reader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));
                    var tmpList = new List<Asn1Filter>();
                    Asn1Filter tmpItem;

                    while (collectionReader.HasData)
                    {
                        Asn1Filter.Decode(collectionReader, rebind, out tmpItem);
                        tmpList.Add(tmpItem);
                    }

                    decoded.Or = tmpList.ToArray();
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                Asn1Filter tmpNot;
                Asn1Filter.Decode(explicitReader, rebind, out tmpNot);
                decoded.Not = tmpNot;

                explicitReader.ThrowIfNotEmpty();
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                Asn1AttributeValueAssertion tmpEqualityMatch;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 3), rebind, out tmpEqualityMatch);
                decoded.EqualityMatch = tmpEqualityMatch;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                Asn1SubstringFilter tmpSubstrings;
                Asn1SubstringFilter.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 4), rebind, out tmpSubstrings);
                decoded.Substrings = tmpSubstrings;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 5)))
            {
                Asn1AttributeValueAssertion tmpGreaterOrEqual;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 5), rebind, out tmpGreaterOrEqual);
                decoded.GreaterOrEqual = tmpGreaterOrEqual;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                Asn1AttributeValueAssertion tmpLessOrEqual;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 6), rebind, out tmpLessOrEqual);
                decoded.LessOrEqual = tmpLessOrEqual;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {

                if (reader.TryReadPrimitiveOctetString(out tmpSpan, new Asn1Tag(TagClass.ContextSpecific, 7)))
                {
                    decoded.Present = rebindSpan.Overlaps(tmpSpan.Span, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
                }
                else
                {
                    decoded.Present = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 7));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                Asn1AttributeValueAssertion tmpApproxMatch;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 8), rebind, out tmpApproxMatch);
                decoded.ApproxMatch = tmpApproxMatch;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                Asn1MatchingRuleAssertion tmpExtensibleMatch;
                Asn1MatchingRuleAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 9), rebind, out tmpExtensibleMatch);
                decoded.ExtensibleMatch = tmpExtensibleMatch;

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1Filter
    {
        internal Asn1Filter[] And;
        internal Asn1Filter[] Or;
        internal Asn1Filter Not;
        internal Asn1AttributeValueAssertion EqualityMatch;
        internal Asn1SubstringFilter Substrings;
        internal Asn1AttributeValueAssertion GreaterOrEqual;
        internal Asn1AttributeValueAssertion LessOrEqual;
        internal ReadOnlyMemory<byte>? Present;
        internal Asn1AttributeValueAssertion ApproxMatch;
        internal Asn1MatchingRuleAssertion ExtensibleMatch;

#if DEBUG
        static Asn1Filter()
        {
            var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();
            Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>
            {
                if (usedTags.TryGetValue(tag, out string existing))
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
                writer.PopSequence();
      
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
                
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 7), Present.Value.Span);
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
            
            Decode(reader, out Asn1Filter decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1Filter decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            reader.ReadNull(expectedTag);
            Decode(reader, out decoded);
        }

        internal static void Decode(AsnReader reader, out Asn1Filter decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1Filter();
            Asn1Tag tag = reader.PeekTag();
            AsnReader collectionReader;
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                // Decode SEQUENCE OF for And
                {
                    collectionReader = reader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
                    var tmpList = new List<Asn1Filter>();
                    Asn1Filter tmpItem;

                    while (collectionReader.HasData)
                    {
                        Asn1Filter.Decode(collectionReader, out tmpItem); 
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
                        Asn1Filter.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.Or = tmpList.ToArray();
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                Asn1Filter tmpNot;
                Asn1Filter.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 2), out tmpNot);
                decoded.Not = tmpNot;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                Asn1AttributeValueAssertion tmpEqualityMatch;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 3), out tmpEqualityMatch);
                decoded.EqualityMatch = tmpEqualityMatch;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                Asn1SubstringFilter tmpSubstrings;
                Asn1SubstringFilter.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 4), out tmpSubstrings);
                decoded.Substrings = tmpSubstrings;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 5)))
            {
                Asn1AttributeValueAssertion tmpGreaterOrEqual;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 5), out tmpGreaterOrEqual);
                decoded.GreaterOrEqual = tmpGreaterOrEqual;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                Asn1AttributeValueAssertion tmpLessOrEqual;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 6), out tmpLessOrEqual);
                decoded.LessOrEqual = tmpLessOrEqual;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 7), out ReadOnlyMemory<byte> tmpPresent))
                {
                    decoded.Present = tmpPresent;
                }
                else
                {
                    decoded.Present = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 7));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                Asn1AttributeValueAssertion tmpApproxMatch;
                Asn1AttributeValueAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 8), out tmpApproxMatch);
                decoded.ApproxMatch = tmpApproxMatch;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                Asn1MatchingRuleAssertion tmpExtensibleMatch;
                Asn1MatchingRuleAssertion.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 9), out tmpExtensibleMatch);
                decoded.ExtensibleMatch = tmpExtensibleMatch;

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

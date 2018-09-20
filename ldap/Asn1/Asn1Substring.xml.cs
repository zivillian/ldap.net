using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

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
                if (usedTags.TryGetValue(tag, out string existing))
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
                
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), Initial.Value.Span);
                wroteValue = true;
            }

            if (Any.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 1), Any.Value.Span);
                wroteValue = true;
            }

            if (Final.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 2), Final.Value.Span);
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
            
            Decode(reader, out Asn1Substring decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1Substring decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            reader.ReadNull(expectedTag);
            Decode(reader, out decoded);
        }

        internal static void Decode(AsnReader reader, out Asn1Substring decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1Substring();
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpInitial))
                {
                    decoded.Initial = tmpInitial;
                }
                else
                {
                    decoded.Initial = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 1), out ReadOnlyMemory<byte> tmpAny))
                {
                    decoded.Any = tmpAny;
                }
                else
                {
                    decoded.Any = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 1));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 2), out ReadOnlyMemory<byte> tmpFinal))
                {
                    decoded.Final = tmpFinal;
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

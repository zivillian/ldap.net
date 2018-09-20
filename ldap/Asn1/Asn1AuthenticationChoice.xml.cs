using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1AuthenticationChoice
    {
        internal ReadOnlyMemory<byte>? Simple;
        internal Asn1SaslCredentials Sasl;

#if DEBUG
        static Asn1AuthenticationChoice()
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
                
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), Simple.Value.Span);
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
            
            Decode(reader, out Asn1AuthenticationChoice decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1AuthenticationChoice decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            reader.ReadNull(expectedTag);
            Decode(reader, out decoded);
        }

        internal static void Decode(AsnReader reader, out Asn1AuthenticationChoice decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1AuthenticationChoice();
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpSimple))
                {
                    decoded.Simple = tmpSimple;
                }
                else
                {
                    decoded.Simple = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                Asn1SaslCredentials tmpSasl;
                Asn1SaslCredentials.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 3), out tmpSasl);
                decoded.Sasl = tmpSasl;

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

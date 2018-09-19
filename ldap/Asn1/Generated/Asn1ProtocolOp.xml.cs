using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1.Generated
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1ProtocolOp
    {
        internal ReadOnlyMemory<byte>? DelRequest;

#if DEBUG
        static Asn1ProtocolOp()
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
            
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 10), "DelRequest");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (DelRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 10), DelRequest.Value.Span);
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }

        internal static Asn1ProtocolOp Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out Asn1ProtocolOp decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1ProtocolOp decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 10), out ReadOnlyMemory<byte> tmpDelRequest))
                {
                    decoded.DelRequest = tmpDelRequest;
                }
                else
                {
                    decoded.DelRequest = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 10));
                }

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

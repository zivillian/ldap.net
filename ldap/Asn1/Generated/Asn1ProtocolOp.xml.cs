using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1.Generated
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1ProtocolOp
    {
        internal Asn1BindRequest? BindRequest;
        internal Asn1BindResponse? BindResponse;
        internal ReadOnlyMemory<byte>? UnbindRequest;
        internal Asn1SearchRequest? SearchRequest;
        internal Asn1SearchResultEntry? SearchResEntry;
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
            
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 0), "BindRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 1), "BindResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 2), "UnbindRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 3), "SearchRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 4), "SearchResEntry");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 10), "DelRequest");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (BindRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                BindRequest.Value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
                wroteValue = true;
            }

            if (BindResponse.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                BindResponse.Value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
                wroteValue = true;
            }

            if (UnbindRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                // Validator for tag constraint for UnbindRequest
                {
                    if (!Asn1Tag.TryParse(UnbindRequest.Value.Span, out Asn1Tag validateTag, out _) ||
                        !validateTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
                    {
                        throw new CryptographicException();
                    }
                }

                writer.WriteEncodedValue(UnbindRequest.Value);
                wroteValue = true;
            }

            if (SearchRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                SearchRequest.Value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 3));
                wroteValue = true;
            }

            if (SearchResEntry.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                SearchResEntry.Value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 4));
                wroteValue = true;
            }

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
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                Asn1BindRequest tmpBindRequest;
                Asn1BindRequest.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 0), out tmpBindRequest);
                decoded.BindRequest = tmpBindRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                Asn1BindResponse tmpBindResponse;
                Asn1BindResponse.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 1), out tmpBindResponse);
                decoded.BindResponse = tmpBindResponse;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                decoded.UnbindRequest = reader.GetEncodedValue();
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                Asn1SearchRequest tmpSearchRequest;
                Asn1SearchRequest.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 3), out tmpSearchRequest);
                decoded.SearchRequest = tmpSearchRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                Asn1SearchResultEntry tmpSearchResEntry;
                Asn1SearchResultEntry.Decode(reader, new Asn1Tag(TagClass.ContextSpecific, 4), out tmpSearchResEntry);
                decoded.SearchResEntry = tmpSearchResEntry;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
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

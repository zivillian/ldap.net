using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1ProtocolOp
    {
        internal Asn1BindRequest BindRequest;
        internal Asn1BindResponse BindResponse;
        internal bool ? UnbindRequest;
        internal Asn1SearchRequest SearchRequest;
        internal Asn1SearchResultEntry SearchResEntry;
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
            
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 0), "BindRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 1), "BindResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 2), "UnbindRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 3), "SearchRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 4), "SearchResEntry");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 10), "DelRequest");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (BindRequest != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                BindRequest.Encode(writer, new Asn1Tag(TagClass.Application, 0));
                wroteValue = true;
            }

            if (BindResponse != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                BindResponse.Encode(writer, new Asn1Tag(TagClass.Application, 1));
                wroteValue = true;
            }

            if (UnbindRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteNull(new Asn1Tag(TagClass.Application, 2));
                wroteValue = true;
            }

            if (SearchRequest != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                SearchRequest.Encode(writer, new Asn1Tag(TagClass.Application, 3));
                wroteValue = true;
            }

            if (SearchResEntry != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                SearchResEntry.Encode(writer, new Asn1Tag(TagClass.Application, 4));
                wroteValue = true;
            }

            if (DelRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteOctetString(new Asn1Tag(TagClass.Application, 10), DelRequest.Value.Span);
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

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1ProtocolOp decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            reader.ReadNull(expectedTag);
            Decode(reader, out decoded);
        }

        internal static void Decode(AsnReader reader, out Asn1ProtocolOp decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1ProtocolOp();
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 0)))
            {
                Asn1BindRequest tmpBindRequest;
                Asn1BindRequest.Decode(reader, new Asn1Tag(TagClass.Application, 0), out tmpBindRequest);
                decoded.BindRequest = tmpBindRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 1)))
            {
                Asn1BindResponse tmpBindResponse;
                Asn1BindResponse.Decode(reader, new Asn1Tag(TagClass.Application, 1), out tmpBindResponse);
                decoded.BindResponse = tmpBindResponse;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 2)))
            {
                reader.ReadNull(new Asn1Tag(TagClass.Application, 2));
                decoded.UnbindRequest = true;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 3)))
            {
                Asn1SearchRequest tmpSearchRequest;
                Asn1SearchRequest.Decode(reader, new Asn1Tag(TagClass.Application, 3), out tmpSearchRequest);
                decoded.SearchRequest = tmpSearchRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 4)))
            {
                Asn1SearchResultEntry tmpSearchResEntry;
                Asn1SearchResultEntry.Decode(reader, new Asn1Tag(TagClass.Application, 4), out tmpSearchResEntry);
                decoded.SearchResEntry = tmpSearchResEntry;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 10)))
            {

                if (reader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.Application, 10), out ReadOnlyMemory<byte> tmpDelRequest))
                {
                    decoded.DelRequest = tmpDelRequest;
                }
                else
                {
                    decoded.DelRequest = reader.ReadOctetString(new Asn1Tag(TagClass.Application, 10));
                }

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

using System;
using System.Collections.Generic;
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
        internal Asn1LDAPResult SearchResultDone;
        internal ReadOnlyMemory<byte>[] SearchResultReference;
        internal Asn1ModifyRequest ModifyRequest;
        internal Asn1LDAPResult ModifyResponse;
        internal Asn1AddRequest AddRequest;
        internal Asn1LDAPResult AddResponse;
        internal ReadOnlyMemory<byte>? DelRequest;
        internal Asn1LDAPResult DelResponse;
        internal Asn1ModifyDNRequest ModifyDNRequest;
        internal Asn1LDAPResult ModifyDNResponse;
        internal Asn1LDAPResult CompareResponse;
        internal int? AbandonRequest;

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
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 5), "SearchResultDone");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 19), "SearchResultReference");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 6), "ModifyRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 7), "ModifyResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 8), "AddRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 9), "AddResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 10), "DelRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 11), "DelResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 12), "ModifyDNRequest");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 13), "ModifyDNResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 15), "CompareResponse");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 16), "AbandonRequest");
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

            if (SearchResultDone != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                SearchResultDone.Encode(writer, new Asn1Tag(TagClass.Application, 5));
                wroteValue = true;
            }

            if (SearchResultReference != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                

                writer.PushSequence(new Asn1Tag(TagClass.Application, 19));
                for (int i = 0; i < SearchResultReference.Length; i++)
                {
                    writer.WriteOctetString(SearchResultReference[i].Span); 
                }
                writer.PopSequence(new Asn1Tag(TagClass.Application, 19));

                wroteValue = true;
            }

            if (ModifyRequest != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                ModifyRequest.Encode(writer, new Asn1Tag(TagClass.Application, 6));
                wroteValue = true;
            }

            if (ModifyResponse != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                ModifyResponse.Encode(writer, new Asn1Tag(TagClass.Application, 7));
                wroteValue = true;
            }

            if (AddRequest != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                AddRequest.Encode(writer, new Asn1Tag(TagClass.Application, 8));
                wroteValue = true;
            }

            if (AddResponse != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                AddResponse.Encode(writer, new Asn1Tag(TagClass.Application, 9));
                wroteValue = true;
            }

            if (DelRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteOctetString(new Asn1Tag(TagClass.Application, 10), DelRequest.Value.Span);
                wroteValue = true;
            }

            if (DelResponse != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                DelResponse.Encode(writer, new Asn1Tag(TagClass.Application, 11));
                wroteValue = true;
            }

            if (ModifyDNRequest != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                ModifyDNRequest.Encode(writer, new Asn1Tag(TagClass.Application, 12));
                wroteValue = true;
            }

            if (ModifyDNResponse != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                ModifyDNResponse.Encode(writer, new Asn1Tag(TagClass.Application, 13));
                wroteValue = true;
            }

            if (CompareResponse != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                CompareResponse.Encode(writer, new Asn1Tag(TagClass.Application, 15));
                wroteValue = true;
            }

            if (AbandonRequest.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteInteger(new Asn1Tag(TagClass.Application, 16), AbandonRequest.Value);
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
            AsnReader collectionReader;
            
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
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 5)))
            {
                Asn1LDAPResult tmpSearchResultDone;
                Asn1LDAPResult.Decode(reader, new Asn1Tag(TagClass.Application, 5), out tmpSearchResultDone);
                decoded.SearchResultDone = tmpSearchResultDone;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 19)))
            {

                // Decode SEQUENCE OF for SearchResultReference
                {
                    collectionReader = reader.ReadSequence(new Asn1Tag(TagClass.Application, 19));
                    var tmpList = new List<ReadOnlyMemory<byte>>();
                    ReadOnlyMemory<byte> tmpItem;

                    while (collectionReader.HasData)
                    {

                        if (collectionReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmp))
                        {
                            tmpItem = tmp;
                        }
                        else
                        {
                            tmpItem = collectionReader.ReadOctetString();
                        }
 
                        tmpList.Add(tmpItem);
                    }

                    decoded.SearchResultReference = tmpList.ToArray();
                }

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 6)))
            {
                Asn1ModifyRequest tmpModifyRequest;
                Asn1ModifyRequest.Decode(reader, new Asn1Tag(TagClass.Application, 6), out tmpModifyRequest);
                decoded.ModifyRequest = tmpModifyRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 7)))
            {
                Asn1LDAPResult tmpModifyResponse;
                Asn1LDAPResult.Decode(reader, new Asn1Tag(TagClass.Application, 7), out tmpModifyResponse);
                decoded.ModifyResponse = tmpModifyResponse;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 8)))
            {
                Asn1AddRequest tmpAddRequest;
                Asn1AddRequest.Decode(reader, new Asn1Tag(TagClass.Application, 8), out tmpAddRequest);
                decoded.AddRequest = tmpAddRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 9)))
            {
                Asn1LDAPResult tmpAddResponse;
                Asn1LDAPResult.Decode(reader, new Asn1Tag(TagClass.Application, 9), out tmpAddResponse);
                decoded.AddResponse = tmpAddResponse;

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
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 11)))
            {
                Asn1LDAPResult tmpDelResponse;
                Asn1LDAPResult.Decode(reader, new Asn1Tag(TagClass.Application, 11), out tmpDelResponse);
                decoded.DelResponse = tmpDelResponse;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 12)))
            {
                Asn1ModifyDNRequest tmpModifyDNRequest;
                Asn1ModifyDNRequest.Decode(reader, new Asn1Tag(TagClass.Application, 12), out tmpModifyDNRequest);
                decoded.ModifyDNRequest = tmpModifyDNRequest;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 13)))
            {
                Asn1LDAPResult tmpModifyDNResponse;
                Asn1LDAPResult.Decode(reader, new Asn1Tag(TagClass.Application, 13), out tmpModifyDNResponse);
                decoded.ModifyDNResponse = tmpModifyDNResponse;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 15)))
            {
                Asn1LDAPResult tmpCompareResponse;
                Asn1LDAPResult.Decode(reader, new Asn1Tag(TagClass.Application, 15), out tmpCompareResponse);
                decoded.CompareResponse = tmpCompareResponse;

            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 16)))
            {

                if (reader.TryReadInt32(new Asn1Tag(TagClass.Application, 16), out int tmpAbandonRequest))
                {
                    decoded.AbandonRequest = tmpAbandonRequest;
                }
                else
                {
                    reader.ThrowIfNotEmpty();
                }

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}

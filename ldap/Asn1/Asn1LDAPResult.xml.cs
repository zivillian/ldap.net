using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1LDAPResult
    {
        internal ResultCode ResultCode;
        internal ReadOnlyMemory<byte> MatchedDN;
        internal ReadOnlyMemory<byte> DiagnosticMessage;
        internal ReadOnlyMemory<byte>[] Referral;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteEnumeratedValue(ResultCode);
            writer.WriteOctetString(MatchedDN.Span);
            writer.WriteOctetString(DiagnosticMessage.Span);

            if (Referral != null)
            {

                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                for (int i = 0; i < Referral.Length; i++)
                {
                    writer.WriteOctetString(Referral[i].Span); 
                }
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            }

            writer.PopSequence(tag);
        }

        internal static Asn1LDAPResult Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1LDAPResult Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1LDAPResult decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1LDAPResult decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1LDAPResult decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1LDAPResult();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            
            decoded.ResultCode = sequenceReader.GetEnumeratedValue<ResultCode>();

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpMatchedDN))
            {
                decoded.MatchedDN = tmpMatchedDN;
            }
            else
            {
                decoded.MatchedDN = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpDiagnosticMessage))
            {
                decoded.DiagnosticMessage = tmpDiagnosticMessage;
            }
            else
            {
                decoded.DiagnosticMessage = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {

                // Decode SEQUENCE OF for Referral
                {
                    collectionReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
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

                    decoded.Referral = tmpList.ToArray();
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

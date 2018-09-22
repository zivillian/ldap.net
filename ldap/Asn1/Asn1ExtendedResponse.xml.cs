using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1ExtendedResponse
    {
        internal ResultCode ResultCode;
        internal ReadOnlyMemory<byte> MatchedDN;
        internal ReadOnlyMemory<byte> DiagnosticMessage;
        internal ReadOnlyMemory<byte>[] Referral;
        internal ReadOnlyMemory<byte>? Name;
        internal ReadOnlyMemory<byte>? Value;
      
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


            if (Name.HasValue)
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 10), Name.Value.Span);
            }


            if (Value.HasValue)
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 11), Value.Value.Span);
            }

            writer.PopSequence(tag);
        }

        internal static Asn1ExtendedResponse Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1ExtendedResponse Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1ExtendedResponse decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1ExtendedResponse decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1ExtendedResponse decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1ExtendedResponse();
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


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 10), out ReadOnlyMemory<byte> tmpName))
                {
                    decoded.Name = tmpName;
                }
                else
                {
                    decoded.Name = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 10));
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 11)))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 11), out ReadOnlyMemory<byte> tmpValue))
                {
                    decoded.Value = tmpValue;
                }
                else
                {
                    decoded.Value = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 11));
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

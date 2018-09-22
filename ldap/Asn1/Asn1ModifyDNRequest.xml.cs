using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1ModifyDNRequest
    {
        internal ReadOnlyMemory<byte> Entry;
        internal ReadOnlyMemory<byte> NewRDN;
        internal bool DeleteOldRDN;
        internal ReadOnlyMemory<byte>? NewSuperior;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(Entry.Span);
            writer.WriteOctetString(NewRDN.Span);
            writer.WriteBoolean(DeleteOldRDN);

            if (NewSuperior.HasValue)
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), NewSuperior.Value.Span);
            }

            writer.PopSequence(tag);
        }

        internal static Asn1ModifyDNRequest Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1ModifyDNRequest Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1ModifyDNRequest decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1ModifyDNRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1ModifyDNRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1ModifyDNRequest();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpEntry))
            {
                decoded.Entry = tmpEntry;
            }
            else
            {
                decoded.Entry = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpNewRDN))
            {
                decoded.NewRDN = tmpNewRDN;
            }
            else
            {
                decoded.NewRDN = sequenceReader.ReadOctetString();
            }

            decoded.DeleteOldRDN = sequenceReader.ReadBoolean();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpNewSuperior))
                {
                    decoded.NewSuperior = tmpNewSuperior;
                }
                else
                {
                    decoded.NewSuperior = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

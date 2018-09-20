using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SaslCredentials
    {
        internal ReadOnlyMemory<byte> Mechanism;
        internal ReadOnlyMemory<byte>? Credentials;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteOctetString(Mechanism.Span);

            if (Credentials.HasValue)
            {
                writer.WriteOctetString(Credentials.Value.Span);
            }

            writer.PopSequence(tag);
        }

        internal static Asn1SaslCredentials Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1SaslCredentials Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1SaslCredentials decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1SaslCredentials decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1SaslCredentials decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1SaslCredentials();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpMechanism))
            {
                decoded.Mechanism = tmpMechanism;
            }
            else
            {
                decoded.Mechanism = sequenceReader.ReadOctetString();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpCredentials))
                {
                    decoded.Credentials = tmpCredentials;
                }
                else
                {
                    decoded.Credentials = sequenceReader.ReadOctetString();
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

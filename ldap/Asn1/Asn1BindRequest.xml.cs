using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1BindRequest
    {
        internal byte Version;
        internal ReadOnlyMemory<byte> Name;
        internal Asn1AuthenticationChoice Authentication;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteInteger(Version);
            writer.WriteOctetString(Name.Span);
            Authentication.Encode(writer);
            writer.PopSequence(tag);
        }

        internal static Asn1BindRequest Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1BindRequest Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1BindRequest decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1BindRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1BindRequest decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (!sequenceReader.TryReadUInt8(out decoded.Version))
            {
                sequenceReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpName))
            {
                decoded.Name = tmpName;
            }
            else
            {
                decoded.Name = sequenceReader.ReadOctetString();
            }

            Asn1AuthenticationChoice.Decode(sequenceReader, out decoded.Authentication);

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

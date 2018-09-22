using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1MatchingRuleAssertion
    {
        internal ReadOnlyMemory<byte>? MatchingRule;
        internal ReadOnlyMemory<byte>? Type;
        internal ReadOnlyMemory<byte> Value;
        internal bool DNAttributes;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            

            if (MatchingRule.HasValue)
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 1), MatchingRule.Value.Span);
            }


            if (Type.HasValue)
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 2), Type.Value.Span);
            }

            writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 3), Value.Span);
            writer.WriteBoolean(new Asn1Tag(TagClass.ContextSpecific, 4), DNAttributes);
            writer.PopSequence(tag);
        }

        internal static Asn1MatchingRuleAssertion Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1MatchingRuleAssertion Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1MatchingRuleAssertion decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1MatchingRuleAssertion decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1MatchingRuleAssertion decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new Asn1MatchingRuleAssertion();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 1), out ReadOnlyMemory<byte> tmpMatchingRule))
                {
                    decoded.MatchingRule = tmpMatchingRule;
                }
                else
                {
                    decoded.MatchingRule = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 1));
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {

                if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 2), out ReadOnlyMemory<byte> tmpType))
                {
                    decoded.Type = tmpType;
                }
                else
                {
                    decoded.Type = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 2));
                }

            }


            if (sequenceReader.TryGetPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 3), out ReadOnlyMemory<byte> tmpValue))
            {
                decoded.Value = tmpValue;
            }
            else
            {
                decoded.Value = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 3));
            }

            decoded.DNAttributes = sequenceReader.ReadBoolean(new Asn1Tag(TagClass.ContextSpecific, 4));

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

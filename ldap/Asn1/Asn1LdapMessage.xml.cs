using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Asn1LdapMessage
    {
        internal int MessageID;
        internal Asn1ProtocolOp ProtocolOp;
        internal Asn1Control[] Controls;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteInteger(MessageID);
            ProtocolOp.Encode(writer);

            if (Controls != null)
            {

                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                for (int i = 0; i < Controls.Length; i++)
                {
                    Controls[i].Encode(writer); 
                }
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            }

            writer.PopSequence(tag);
        }

        internal static Asn1LdapMessage Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static Asn1LdapMessage Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out Asn1LdapMessage decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out Asn1LdapMessage decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out Asn1LdapMessage decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            

            if (!sequenceReader.TryReadInt32(out decoded.MessageID))
            {
                sequenceReader.ThrowIfNotEmpty();
            }

            Asn1ProtocolOp.Decode(sequenceReader, out decoded.ProtocolOp);

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                // Decode SEQUENCE OF for Controls
                {
                    collectionReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    var tmpList = new List<Asn1Control>();
                    Asn1Control tmpItem;

                    while (collectionReader.HasData)
                    {
                        Asn1Control.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.Controls = tmpList.ToArray();
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}

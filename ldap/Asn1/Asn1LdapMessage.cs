using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1LdapMessage 
    {
        /*
         * LDAPMessage ::= SEQUENCE {
         *      messageID       MessageID,
         *      protocolOp      CHOICE {
         *           bindRequest           BindRequest,
         *           bindResponse          BindResponse,
         *           unbindRequest         UnbindRequest,
         *           searchRequest         SearchRequest,
         *           searchResEntry        SearchResultEntry,
         *           searchResDone         SearchResultDone,
         *           searchResRef          SearchResultReference,
         *           modifyRequest         ModifyRequest,
         *           modifyResponse        ModifyResponse,
         *           addRequest            AddRequest,
         *           addResponse           AddResponse,
         *           delRequest            DelRequest,
         *           delResponse           DelResponse,
         *           modDNRequest          ModifyDNRequest,
         *           modDNResponse         ModifyDNResponse,
         *           compareRequest        CompareRequest,
         *           compareResponse       CompareResponse,
         *           abandonRequest        AbandonRequest,
         *           extendedReq           ExtendedRequest,
         *           extendedResp          ExtendedResponse,
         *           ...,
         *           intermediateResponse  IntermediateResponse },
         *      controls       [0] Controls OPTIONAL }
         *
         * MessageID ::= INTEGER (0 ..  maxInt)
         *
         * maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
         *
         * Controls ::= SEQUENCE OF control Control
         */

        public int Id;

        public Asn1ProtocolOpChoice ProtocolOp;
        
        [OptionalValue]
        [SequenceOf]
        [ExpectedTag(TagClass.ContextSpecific, 0)]
        public Asn1Control[] Controls;
    }
}
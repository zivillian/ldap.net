using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [Choice]
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1ProtocolOpChoice
    {
        /*
         * protocolOp      CHOICE {
         *      bindRequest           BindRequest,
         *      bindResponse          BindResponse,
         *      unbindRequest         UnbindRequest,
         *      searchRequest         SearchRequest,
         *      searchResEntry        SearchResultEntry,
         *      searchResDone         SearchResultDone,
         *      searchResRef          SearchResultReference,
         *      modifyRequest         ModifyRequest,
         *      modifyResponse        ModifyResponse,
         *      addRequest            AddRequest,
         *      addResponse           AddResponse,
         *      delRequest            DelRequest,
         *      delResponse           DelResponse,
         *      modDNRequest          ModifyDNRequest,
         *      modDNResponse         ModifyDNResponse,
         *      compareRequest        CompareRequest,
         *      compareResponse       CompareResponse,
         *      abandonRequest        AbandonRequest,
         *      extendedReq           ExtendedRequest,
         *      extendedResp          ExtendedResponse,
         *      ...,
         *      intermediateResponse  IntermediateResponse }
         */

        [ExpectedTag(TagClass.Application, 0)]
        public Asn1BindRequest? BindRequest;

        [ExpectedTag(TagClass.Application, 1)]
        public Asn1BindResponse? BindResponse;

        /*
         * UnbindRequest ::= [APPLICATION 2] NULL
         */
        [ExpectedTag(TagClass.Application, 2)]
        [AnyValue]
        //TODO
        public ReadOnlyMemory<byte>? UnbindRequest;

        [ExpectedTag(TagClass.Application, 3)]
        public Asn1SearchRequest? SearchRequest;

        //public Asn1SearchResEntry? SearchResultEntry;

        //public Asn1SearchResDone? SearchResultDone;

        //public Asn1SearchResRef? SearchResultReference;

        //public Asn1ModifyRequest? ModifyRequest;

        //public Asn1ModifyResponse? ModifyResponse;

        //public Asn1AddRequest? AddRequest;

        //public Asn1AddResponse? AddResponse;

        /*
         * DelRequest ::= [APPLICATION 10] LDAPDN
         *
         * LDAPDN ::= LDAPString
         *
         * LDAPString ::= OCTET STRING -- UTF-8 encoded
         *
         */
        [ExpectedTag(TagClass.Application, 10)]
        [OctetString]
        public ReadOnlyMemory<byte>? DelRequest;

        //public Asn1DelResponse? DelResponse;

        //public Asn1ModDNRequest? ModifyDNRequest;

        //public Asn1ModDNResponse? ModifyDNResponse;

        //public Asn1CompareRequest? CompareRequest;

        //public Asn1CompareResponse? CompareResponse;

        //public Asn1AbandonRequest? AbandonRequest;

        //public Asn1ExtendedReq? ExtendedRequest;

        //public Asn1ExtendedResp? ExtendedResponse;
    }
}
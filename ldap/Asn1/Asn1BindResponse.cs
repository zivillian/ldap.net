using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1BindResponse
    {
        /*
         * SEQUENCE {
         *     COMPONENTS OF LDAPResult,
         *     serverSaslCreds    [7] OCTET STRING OPTIONAL }
         *
         * LDAPResult ::= SEQUENCE {
         *     resultCode         ENUMERATED {
         *          ...  },
         *     matchedDN          LDAPDN,
         *     diagnosticMessage  LDAPString,
         *     referral           [3] Referral OPTIONAL }
         *
         * Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
         *
         * URI ::= LDAPString     -- limited to characters permitted in
         *          -- URIs
         */
        public ResultCode ResultCode;

        [OctetString] 
        public ReadOnlyMemory<byte> MatchedDN;
        
        [OctetString]
        public ReadOnlyMemory<byte> DiagnosticMessage;

        [ExpectedTag(TagClass.ContextSpecific, 3)]
        [OptionalValue]
        [SequenceOf]
        public Asn1Referral[] Referral;

        [ExpectedTag(TagClass.ContextSpecific, 7)]
        [OctetString]
        [OptionalValue]
        public ReadOnlyMemory<byte>? ServerSaslCreds;
    }

    public struct Asn1Referral
    {
        [OctetString]
        public ReadOnlyMemory<byte> Uri;
    }
}
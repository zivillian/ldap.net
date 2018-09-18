using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace zivillian.ldap.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Asn1SearchRequest
    {
        /*
         * SearchRequest ::= [APPLICATION 3] SEQUENCE {
         *      baseObject      LDAPDN,
         *      scope           ENUMERATED {
         *           ...  },
         *      derefAliases    ENUMERATED { ... },
         *      sizeLimit       INTEGER (0 ..  maxInt),
         *      timeLimit       INTEGER (0 ..  maxInt),
         *      typesOnly       BOOLEAN,
         *      filter          Filter,
         *      attributes      AttributeSelection }
         *
         * AttributeSelection ::= SEQUENCE OF selector LDAPString
         *   -- The LDAPString is constrained to
         *   -- <attributeSelector> in Section 4.5.1.8
         */

        [OctetString] 
        public ReadOnlyMemory<byte> BaseObject;

        public SearchScope Scope;

        public DerefAliases DerefAliases;

        public int SizeLimit;

        public int TimeLimit;

        public bool TypesOnly;

        public Asn1Filter Filter;

        //TODO
        [AnyValue]
        public ReadOnlyMemory<byte> Attributes;
    }
}
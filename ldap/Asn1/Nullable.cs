using System;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SearchRequest
    {
        private Asn1SearchRequest()
        {
            Filter = null!;
        }

        public Asn1SearchRequest(ReadOnlyMemory<byte> baseObject, SearchScope scope, DerefAliases derefAliases, int timeLimit, bool typesOnly, Asn1Filter filter)
        {
            BaseObject = baseObject;
            Scope = scope;
            DerefAliases = derefAliases;
            TimeLimit = timeLimit;
            TypesOnly = typesOnly;
            Filter = filter;
        }
    }

    internal sealed partial class Asn1Change
    {
        private Asn1Change()
        {
            Modification = null!;
        }

        public Asn1Change(ChangeOperation operation, Asn1PartialAttribute modification)
        {
            Operation = operation;
            Modification = modification;
        }
    }

    internal sealed partial class Asn1BindRequest
    {
        private Asn1BindRequest()
        {
            Authentication = null!;
        }

        public Asn1BindRequest(int version, ReadOnlyMemory<byte> name, Asn1AuthenticationChoice authentication)
        {
            Version = version;
            Name = name;
            Authentication = authentication;
        }
    }

    internal sealed partial class Asn1CompareRequest
    {
        private Asn1CompareRequest()
        {
            Assertion = null!;
        }

        public Asn1CompareRequest(ReadOnlyMemory<byte> entry, Asn1AttributeValueAssertion assertion)
        {
            Entry = entry;
            Assertion = assertion;
        }
    }

    internal sealed partial class Asn1LdapMessage
    {
        private Asn1LdapMessage()
        {
            ProtocolOp = null!;
        }

        public Asn1LdapMessage(int messageId, Asn1ProtocolOp protocolOp, Asn1Control[]? controls)
        {
            Controls = controls;
            ProtocolOp = protocolOp;
            MessageID = messageId;
        }
    }
}

using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAddRequest : LdapRequestMessage
    {
        public LdapDistinguishedName Entry { get; }

        public IReadOnlyList<LdapAttribute> Attributes { get; }

        internal LdapAddRequest(Asn1AddRequest add, Asn1LdapMessage message)
            : base(message)
        {
            Entry = new LdapDistinguishedName(add.Entry.Span);
            if (add.Attributes.Length == 0)
                throw new ArgumentException("at least one attribute required");
            var attributes = new LdapAttribute[add.Attributes.Length];
            for (int i = 0; i < add.Attributes.Length; i++)
            {
                attributes[i] = new LdapAttribute(add.Attributes[i]);
            }
            Attributes = attributes;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var attributes = new Asn1PartialAttribute[Attributes.Count];
            if (attributes.Length == 0)
                throw new ArgumentException("at least one attribute required");
            for (int i = 0; i < Attributes.Count; i++)
            {
                attributes[i] = Attributes[i].GetAsn();
            }
            op.AddRequest = new Asn1AddRequest
            {
                Entry = Entry.GetBytes(),
                Attributes = attributes
            };
        }
    }
}
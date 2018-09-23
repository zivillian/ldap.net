using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAddRequest : LdapRequestMessage
    {
        public LdapDistinguishedName Entry { get; }

        public LdapAttribute[] Attributes { get; }

        internal LdapAddRequest(Asn1LdapMessage message)
            : base(message)
        {
            var add = message.ProtocolOp.AddRequest;
            Entry = new LdapDistinguishedName(add.Entry.Span);
            if (add.Attributes.Length == 0)
                throw new ArgumentException("at least one attribute required");
            Attributes = new LdapAttribute[add.Attributes.Length];
            for (int i = 0; i < add.Attributes.Length; i++)
            {
                Attributes[i] = new LdapAttribute(add.Attributes[i]);
            }
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var attributes = new Asn1PartialAttribute[Attributes.Length];
            if (attributes.Length == 0)
                throw new ArgumentException("at least one attribute required");
            for (int i = 0; i < Attributes.Length; i++)
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
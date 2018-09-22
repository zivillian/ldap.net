using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAddRequest : LdapRequestMessage
    {
        public string Entry { get; }

        public LdapAttribute[] Attributes { get; }

        internal LdapAddRequest(Asn1LdapMessage message)
            : base(message)
        {
            var add = message.ProtocolOp.AddRequest;
            Entry = Encoding.UTF8.GetString(add.Entry.Span);
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
                Entry = Encoding.UTF8.GetBytes(Entry),
                Attributes = attributes
            };
        }
    }

    public class LdapModifyRequest : LdapRequestMessage
    {
        public string Object { get; }

        public LdapChange[] Changes { get; }

        internal LdapModifyRequest(Asn1LdapMessage message)
            : base(message)
        {
            var modify = message.ProtocolOp.ModifyRequest;
            Object = Encoding.UTF8.GetString(modify.Object.Span);
            Changes = new LdapChange[modify.Changes.Length];
            for (int i = 0; i < modify.Changes.Length; i++)
            {
                Changes[i] = new LdapChange(modify.Changes[i]);
            }
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var modify = op.ModifyRequest = new Asn1ModifyRequest
            {
                Object = Encoding.UTF8.GetBytes(Object),
                Changes = new Asn1Change[Changes.Length]
            };
            for (int i = 0; i < Changes.Length; i++)
            {
                modify.Changes[i] = Changes[i].GetAsn();
            }
        }
    }

    public class LdapChange
    {
        public ChangeOperation Operation { get; }

        public LdapAttribute Modification { get; }

        internal LdapChange(Asn1Change change)
        {
            Operation = change.Operation;
            Modification = new LdapAttribute(change.Modification);
        }

        internal Asn1Change GetAsn()
        {
            return new Asn1Change
            {
                Operation = Operation,
                Modification = Modification.GetAsn()
            };
        }
    }
}
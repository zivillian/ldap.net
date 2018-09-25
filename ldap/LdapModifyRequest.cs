using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapModifyRequest : LdapRequestMessage
    {
        public LdapDistinguishedName Object { get; }

        public LdapChange[] Changes { get; }

        internal LdapModifyRequest(Asn1LdapMessage message)
            : base(message)
        {
            var modify = message.ProtocolOp.ModifyRequest;
            Object = new LdapDistinguishedName(modify.Object.Span);
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
                Object = Object.GetBytes(),
                Changes = new Asn1Change[Changes.Length]
            };
            for (int i = 0; i < Changes.Length; i++)
            {
                modify.Changes[i] = Changes[i].GetAsn();
            }
        }
    }
}
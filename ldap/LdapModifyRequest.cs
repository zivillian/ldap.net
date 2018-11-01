using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapModifyRequest : LdapRequestMessage
    {
        public LdapDistinguishedName ObjectDN { get; }

        public IReadOnlyList<LdapChange> Changes { get; }

        internal LdapModifyRequest(Asn1LdapMessage message)
            : base(message)
        {
            var modify = message.ProtocolOp.ModifyRequest;
            ObjectDN = new LdapDistinguishedName(modify.Object.Span);
            var changes = new LdapChange[modify.Changes.Length];
            for (int i = 0; i < modify.Changes.Length; i++)
            {
                changes[i] = new LdapChange(modify.Changes[i]);
            }
            Changes = changes;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            var modify = op.ModifyRequest = new Asn1ModifyRequest
            {
                Object = ObjectDN.GetBytes(),
                Changes = new Asn1Change[Changes.Count]
            };
            for (int i = 0; i < Changes.Count; i++)
            {
                modify.Changes[i] = Changes[i].GetAsn();
            }
        }
    }
}
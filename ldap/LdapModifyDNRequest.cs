using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapModifyDNRequest : LdapRequestMessage
    {
        public LdapDistinguishedName Entry { get; }

        public bool DeleteOldRDN { get; }
        
        public LdapRelativeDistinguishedName NewRDN { get; }

        public LdapDistinguishedName NewSuperior { get; }

        internal LdapModifyDNRequest(Asn1LdapMessage message) : base(message)
        {
            var modify = message.ProtocolOp.ModifyDNRequest;
            Entry = new LdapDistinguishedName(modify.Entry.Span);
            NewRDN = new LdapRelativeDistinguishedName(modify.NewRDN.Span.LdapString());
            DeleteOldRDN = modify.DeleteOldRDN;
            if (modify.NewSuperior.HasValue)
                NewSuperior = new LdapDistinguishedName(modify.NewSuperior.Value.Span);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ModifyDNRequest = new Asn1ModifyDNRequest
            {
                Entry = Entry.GetBytes(),
                NewRDN = NewRDN.GetBytes(),
                DeleteOldRDN = DeleteOldRDN,
            };
            if (NewSuperior != null)
                op.ModifyDNRequest.NewSuperior = NewSuperior.GetBytes();
        }
    }
}
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapModifyDNRequest : LdapRequestMessage
    {
        public string Entry { get; }

        public bool DeleteOldRDN { get; }
        
        public string NewRDN { get; }

        public string NewSuperior { get; }

        internal LdapModifyDNRequest(Asn1LdapMessage message) : base(message)
        {
            var modify = message.ProtocolOp.ModifyDNRequest;
            Entry = Encoding.UTF8.GetString(modify.Entry.Span);
            NewRDN = Encoding.UTF8.GetString(modify.NewRDN.Span);
            DeleteOldRDN = modify.DeleteOldRDN;
            if (modify.NewSuperior.HasValue)
                NewSuperior = Encoding.UTF8.GetString(modify.NewSuperior.Value.Span);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.ModifyDNRequest = new Asn1ModifyDNRequest
            {
                Entry = Encoding.UTF8.GetBytes(Entry),
                NewRDN = Encoding.UTF8.GetBytes(NewRDN),
                DeleteOldRDN = DeleteOldRDN,
            };
            if (NewSuperior != null)
                op.ModifyDNRequest.NewSuperior = Encoding.UTF8.GetBytes(NewSuperior);
        }
    }
}
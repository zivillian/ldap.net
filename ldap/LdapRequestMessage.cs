using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapRequestMessage
    {
        public int Id { get; }

        public LdapControl[] Controls { get; set; }

        internal LdapRequestMessage(Asn1LdapMessage message)
        {
            Id = message.Id;
            Controls = LdapControl.Create(message.Controls);
        }

        internal static LdapRequestMessage Create(Asn1LdapMessage message)
        {
            if (message.ProtocolOp.BindRequest != null)
            {
                return new LdapBindRequest(message);
            }
            else if (message.ProtocolOp.BindResponse != null)
            {
                return new LdapBindResponse(message.ProtocolOp.BindResponse.Value, message);
            }
            else if (message.ProtocolOp.DelRequest != null)
            {
                return new LdapDeleteRequest(message);
            }
            else if (message.ProtocolOp.SearchRequest != null)
            {
                return new LdapSearchRequest(message);
            }
            else if (message.ProtocolOp.UnbindRequest != null)
            {
                return new LdapUnbindRequest(message);
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}
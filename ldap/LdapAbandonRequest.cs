using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAbandonRequest : LdapRequestMessage
    {
        public int MessageId { get; }

        internal LdapAbandonRequest(int messageId, Asn1LdapMessage message) : base(message)
        {
            MessageId = messageId;
            if (MessageId < 0)
                throw new LdapProtocolException("invalid messageID");
        }

        internal LdapAbandonRequest(int abandonId, int messageId, LdapControl[] controls)
            : base(messageId, controls)
        {
            MessageId = abandonId;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.AbandonRequest = MessageId;
        }
    }
}
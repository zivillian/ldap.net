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
            Id = message.MessageID;
            if (Id < 0)
                throw new LdapProtocolException("invalid messageID");
            Controls = LdapControl.Create(message.Controls);
        }

        internal LdapRequestMessage(int messageId, LdapControl[] controls)
        {
            if (Id < 0)
                throw new ArgumentOutOfRangeException(nameof(messageId));
            Id = messageId;
            Controls = controls;
        }

        internal Asn1LdapMessage GetAsn()
        {
            var result = new Asn1LdapMessage
            {
                MessageID = Id,
                Controls = LdapControl.Create(Controls),
                ProtocolOp = new Asn1ProtocolOp()
            };
            SetProtocolOp(result.ProtocolOp);
            return result;
        }

        internal abstract void SetProtocolOp(Asn1ProtocolOp op);

        internal static LdapRequestMessage Create(Asn1LdapMessage message)
        {
            if (message.ProtocolOp.BindRequest != null)
            {
                return new LdapBindRequest(message);
            }
            else if (message.ProtocolOp.BindResponse != null)
            {
                return new LdapBindResponse(message);
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
            else if (message.ProtocolOp.SearchResEntry != null)
            {
                return new LdapSearchResultEntry(message);
            }
            else if (message.ProtocolOp.SearchResultDone != null)
            {
                return new LdapSearchResultDone(message);
            }
            else if (message.ProtocolOp.SearchResultReference != null)
            {
                return new LdapSearchResultReference(message);
            }
            else if (message.ProtocolOp.ModifyRequest != null)
            {
                return new LdapModifyRequest(message);
            }
            else if (message.ProtocolOp.ModifyResponse != null)
            {
                return new LdapModifyResponse(message);
            }
            else if (message.ProtocolOp.AddRequest != null)
            {
                return new LdapAddRequest(message);
            }
            else if (message.ProtocolOp.AddResponse != null)
            {
                return new LdapAddResponse(message);
            }
            else if (message.ProtocolOp.DelResponse != null)
            {
                return new LdapDeleteResponse(message);
            }
            else if (message.ProtocolOp.ModifyDNRequest != null)
            {
                return new LdapModifyDNRequest(message);
            }
            else if (message.ProtocolOp.ModifyDNResponse != null)
            {
                return new LdapModifyDNResponse(message);
            }
            else if (message.ProtocolOp.CompareRequest != null)
            {
                return new LdapCompareRequest(message);
            }
            else if (message.ProtocolOp.CompareResponse != null)
            {
                return new LdapCompareResponse(message);
            }
            else if (message.ProtocolOp.AbandonRequest != null)
            {
                return new LdapAbandonRequest(message);
            }
            else if (message.ProtocolOp.ExtendedRequest != null)
            {
                return new LdapExtendedRequest(message);
            }
            else if (message.ProtocolOp.ExtendedResponse != null)
            {
                return new LdapExtendedResponse(message);
            }
            else if (message.ProtocolOp.IntermediateResponse != null)
            {
                return new LdapIntermediateResponse(message);
            }
            else
            {
                throw new NotSupportedException("unsupported protocolOp");
            }
        }
    }
}
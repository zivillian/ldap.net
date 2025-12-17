using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapRequestMessage
    {
        public int Id { get; }

        public IReadOnlyList<LdapControl>? Controls { get; set; }

        internal LdapRequestMessage(Asn1LdapMessage message)
        {
            Id = message.MessageID;
            if (Id < 0)
                throw new LdapProtocolException("invalid messageID");
            Controls = LdapControl.Create(message.Controls);
        }

        internal LdapRequestMessage(int messageId, LdapControl[]? controls)
        {
            if (Id < 0)
                throw new ArgumentOutOfRangeException(nameof(messageId));
            Id = messageId;
            Controls = controls;
        }

        internal Asn1LdapMessage GetAsn()
        {
            var result = new Asn1LdapMessage
            (
                Id,
                new Asn1ProtocolOp(),
                LdapControl.Create(Controls)
            );
            SetProtocolOp(result.ProtocolOp);
            return result;
        }

        internal abstract void SetProtocolOp(Asn1ProtocolOp op);

        internal static LdapRequestMessage Create(Asn1LdapMessage message)
        {
            if (message.ProtocolOp.BindRequest is not null)
            {
                return new LdapBindRequest(message.ProtocolOp.BindRequest, message);
            }
            else if (message.ProtocolOp.BindResponse is not null)
            {
                return new LdapBindResponse(message.ProtocolOp.BindResponse, message);
            }
            else if (message.ProtocolOp.DelRequest is not null)
            {
                return new LdapDeleteRequest(message.ProtocolOp.DelRequest.Value, message);
            }
            else if (message.ProtocolOp.SearchRequest is not null)
            {
                return new LdapSearchRequest(message.ProtocolOp.SearchRequest, message);
            }
            else if (message.ProtocolOp.UnbindRequest is not null)
            {
                return new LdapUnbindRequest(message);//todo why is UnbindRequest not used?
            }
            else if (message.ProtocolOp.SearchResEntry is not null)
            {
                return new LdapSearchResultEntry(message.ProtocolOp.SearchResEntry, message);
            }
            else if (message.ProtocolOp.SearchResultDone is not null)
            {
                return new LdapSearchResultDone(message.ProtocolOp.SearchResultDone, message);
            }
            else if (message.ProtocolOp.SearchResultReference is not null)
            {
                return new LdapSearchResultReference(message.ProtocolOp.SearchResultReference, message);
            }
            else if (message.ProtocolOp.ModifyRequest is not null)
            {
                return new LdapModifyRequest(message.ProtocolOp.ModifyRequest, message);
            }
            else if (message.ProtocolOp.ModifyResponse is not null)
            {
                return new LdapModifyResponse(message.ProtocolOp.ModifyResponse, message);
            }
            else if (message.ProtocolOp.AddRequest is not null)
            {
                return new LdapAddRequest(message.ProtocolOp.AddRequest, message);
            }
            else if (message.ProtocolOp.AddResponse is not null)
            {
                return new LdapAddResponse(message.ProtocolOp.AddResponse, message);
            }
            else if (message.ProtocolOp.DelResponse is not null)
            {
                return new LdapDeleteResponse(message.ProtocolOp.DelResponse, message);
            }
            else if (message.ProtocolOp.ModifyDNRequest is not null)
            {
                return new LdapModifyDNRequest(message.ProtocolOp.ModifyDNRequest, message);
            }
            else if (message.ProtocolOp.ModifyDNResponse is not null)
            {
                return new LdapModifyDNResponse(message.ProtocolOp.ModifyDNResponse, message);
            }
            else if (message.ProtocolOp.CompareRequest is not null)
            {
                return new LdapCompareRequest(message.ProtocolOp.CompareRequest, message);
            }
            else if (message.ProtocolOp.CompareResponse is not null)
            {
                return new LdapCompareResponse(message.ProtocolOp.CompareResponse, message);
            }
            else if (message.ProtocolOp.AbandonRequest is not null)
            {
                return new LdapAbandonRequest(message.ProtocolOp.AbandonRequest.Value, message);
            }
            else if (message.ProtocolOp.ExtendedRequest is not null)
            {
                return new LdapExtendedRequest(message.ProtocolOp.ExtendedRequest, message);
            }
            else if (message.ProtocolOp.ExtendedResponse is not null)
            {
                return new LdapExtendedResponse(message.ProtocolOp.ExtendedResponse, message);
            }
            else if (message.ProtocolOp.IntermediateResponse is not null)
            {
                return new LdapIntermediateResponse(message.ProtocolOp.IntermediateResponse, message);
            }
            else
            {
                throw new NotSupportedException("unsupported protocolOp");
            }
        }
    }
}
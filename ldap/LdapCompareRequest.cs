using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapCompareRequest : LdapRequestMessage
    {
        public LdapDistinguishedName Entry { get; }

        public LdapAttributeAssertion Assertion { get; }

        internal LdapCompareRequest(Asn1LdapMessage message)
            : base(message)
        {
            var compare = message.ProtocolOp.CompareRequest;
            Entry = new LdapDistinguishedName(compare.Entry.Span);
            Assertion = new LdapAttributeAssertion(compare.Assertion);
        }

        internal LdapCompareRequest(int messageId, string dn, LdapAttributeAssertion assertion, LdapControl[] controls)
            : base(messageId, controls)
        {
            Entry = new LdapDistinguishedName(dn);
            Assertion = assertion;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.CompareRequest = new Asn1CompareRequest
            {
                Entry = Entry.GetBytes(),
                Assertion = Assertion.GetAsn()
            };
        }
    }
}
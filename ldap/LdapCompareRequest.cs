using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapCompareRequest : LdapRequestMessage
    {
        public string Entry { get; }

        public LdapAttributeAssertion Assertion { get; }

        internal LdapCompareRequest(Asn1LdapMessage message)
            : base(message)
        {
            var compare = message.ProtocolOp.CompareRequest;
            Entry = Encoding.UTF8.GetString(compare.Entry.Span);
            Assertion = new LdapAttributeAssertion(compare.Assertion);
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.CompareRequest = new Asn1CompareRequest
            {
                Entry = Encoding.UTF8.GetBytes(Entry),
                Assertion = Assertion.GetAsn()
            };
        }
    }
}
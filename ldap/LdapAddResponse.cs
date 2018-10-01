using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAddResponse : LdapResponseMessage
    {
        internal LdapAddResponse(Asn1LdapMessage message)
            : base(message.ProtocolOp.AddResponse, message)
        {
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op, Asn1LDAPResult result)
        {
            op.AddResponse = result;
        }
    }
}
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapChange
    {
        public ChangeOperation Operation { get; }

        public LdapAttribute Modification { get; }

        internal LdapChange(Asn1Change change)
        {
            Operation = change.Operation;
            Modification = new LdapAttribute(change.Modification);
        }

        internal Asn1Change GetAsn()
        {
            return new Asn1Change
            {
                Operation = Operation,
                Modification = Modification.GetAsn()
            };
        }
    }
}
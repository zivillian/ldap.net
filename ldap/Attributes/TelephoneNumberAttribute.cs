namespace zivillian.ldap.Attributes
{
    public class TelephoneNumberAttribute : PrintableStringLdapAttribute
    {
        private const string _name = "telephoneNumber";

        public TelephoneNumberAttribute()
            : base(_name)
        {
        }

        public override string Oid => "2.5.4.20";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.UserApplication;
    }
}
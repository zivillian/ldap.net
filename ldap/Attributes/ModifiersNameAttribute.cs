namespace zivillian.ldap.Attributes
{
    public class ModifiersNameAttribute : DNLdapAttribute
    {
        private const string _name = "modifiersName";

        public ModifiersNameAttribute()
            :base(_name)
        {
        }

        public override string Oid => "2.5.18.4";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DirectoryOperation;
    }
}
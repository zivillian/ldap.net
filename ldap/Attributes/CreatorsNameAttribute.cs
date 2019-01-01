namespace zivillian.ldap.Attributes
{
    public class CreatorsNameAttribute : DNLdapAttribute
    {
        private const string _name = "creatorsName";

        public CreatorsNameAttribute()
            :base(_name)
        {
        }

        public override string Oid => "2.5.18.3";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DirectoryOperation;
    }
}
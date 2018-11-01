namespace zivillian.ldap.Attributes
{
    public class DescriptionAttribute : DirectoryStringSyntaxLdapAttribute
    {
        private const string _name = "description";

        public DescriptionAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "2.5.4.13";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.UserApplication;
    }
}
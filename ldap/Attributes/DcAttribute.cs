namespace zivillian.ldap.Attributes
{
    public class DcAttribute : IA5StringSyntaxLdapAttribute
    {
        private static readonly string _name = "dc";

        public DcAttribute()
            :base(_name)
        {
        }

        public override string Oid => "0.9.2342.19200300.100.1.25";
        
        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.UserApplication;
    }
}
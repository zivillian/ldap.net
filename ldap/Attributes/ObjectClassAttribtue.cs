namespace zivillian.ldap.Attributes
{
    public class ObjectClassAttribute : OidSyntaxLdapAttribute
    {
        private const string _name = "objectClass";

        public ObjectClassAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "2.5.4.0";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.UserApplication;
    }
}
using System;

namespace zivillian.ldap.Attributes
{
    public class SupportedControlAttribute : OidSyntaxLdapAttribute
    {
        private static readonly string _name = "supportedControl";

        public SupportedControlAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "1.3.6.1.4.1.1466.101.120.13";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;
    }
}
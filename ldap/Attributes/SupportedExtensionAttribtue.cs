using System;

namespace zivillian.ldap.Attributes
{
    public class SupportedExtensionAttribute : OidSyntaxLdapAttribute
    {
        private const string _name = "supportedExtension";

        public SupportedExtensionAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "1.3.6.1.4.1.1466.101.120.7";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;
    }
}
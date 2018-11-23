using System;

namespace zivillian.ldap.Attributes
{
    public class SupportedFeaturesAttribute : OidSyntaxLdapAttribute
    {
        private const string _name = "supportedFeatures";

        public SupportedFeaturesAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "1.3.6.1.4.1.4203.1.3.5";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;
    }
}
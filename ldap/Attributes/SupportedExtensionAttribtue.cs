using System;

namespace zivillian.ldap.Attributes
{
    public class SupportedExtensionAttribute : OidSyntaxLdapAttribute
    {
        public const string ShortName = "supportedExtension";
        public const string OidValue = "1.3.6.1.4.1.1466.101.120.7";

        public SupportedExtensionAttribute()
            : base(ShortName)
        {
        }
        
        public override string Oid => OidValue;

        public override string Name => ShortName;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;
    }
}
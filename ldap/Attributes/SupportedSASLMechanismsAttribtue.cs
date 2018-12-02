using System;

namespace zivillian.ldap.Attributes
{
    public class SupportedSASLMechanismsAttribute : DirectoryStringSyntaxLdapAttribute
    {
        private const string _name = "supportedSASLMechanisms";

        public const string Plain = "PLAIN";
        public const string Anonymous = "ANONYMOUS";

        public SupportedSASLMechanismsAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "1.3.6.1.4.1.1466.101.120.14";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;
    }
}
using System;

namespace zivillian.ldap.Attributes
{
    public class NamingContextsAttribute : AbstractLdapAttribute<LdapDistinguishedName>
    {
        private static readonly string _name = "namingContexts";

        public NamingContextsAttribute() : base(_name)
        {
        }

        public override string Oid => "1.3.6.1.4.1.1466.101.120.5";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;

        protected override ReadOnlyMemory<byte> Serialize(LdapDistinguishedName entry)
        {
            return entry.GetBytes();
        }
    }
}
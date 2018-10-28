using System;
using System.Text;

namespace zivillian.ldap.Attributes
{
    public class AltServerAttribute:AbstractLdapAttribute<Uri>
    {
        private static readonly string _name = "altServer";

        public AltServerAttribute() : base(_name)
        {

        }

        public override string Oid => "1.3.6.1.4.1.1466.101.120.6";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;

        protected override ReadOnlyMemory<byte> Serialize(Uri entry)
        {
            return Encoding.ASCII.GetBytes(entry.AbsoluteUri);
        }
    }
}

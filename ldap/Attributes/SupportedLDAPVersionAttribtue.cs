using System;
using System.Globalization;
using System.Text;

namespace zivillian.ldap.Attributes
{
    public class SupportedLDAPVersionAttribute : AbstractLdapAttribute<long>
    {
        private const string _name = "supportedLDAPVersion";

        public SupportedLDAPVersionAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "1.3.6.1.4.1.1466.101.120.15";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DSAOperation;

        protected override ReadOnlyMemory<byte> Serialize(long entry)
        {
            return entry.ToString(CultureInfo.InvariantCulture).LdapString();
        }
    }
}
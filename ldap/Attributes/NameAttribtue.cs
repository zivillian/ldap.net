using System;

namespace zivillian.ldap.Attributes
{
    public class NameAttribute : DirectoryStringSyntaxLdapAttribute
    {
        private static readonly string _name = "name";

        protected NameAttribute(string nameOrOid)
            :base(nameOrOid)
        {
        }

        public NameAttribute()
            : base(_name)
        {
        }
        
        public override string Oid => "2.5.4.41";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.UserApplication;
    }
}
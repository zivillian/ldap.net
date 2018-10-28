using System.Collections.Generic;
using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    public class OrganizationObjectClass : TopObjectClass
    {
        public OrganizationObjectClass()
        {
            ObjectClass.Entries.Add("organization");
            O = new OAttribute();
        }

        public OAttribute O { get; }

        protected override void GetAttributes(List<AbstractLdapAttribute> result)
        {
            result.Add(O);
            base.GetAttributes(result);
        }
    }
}
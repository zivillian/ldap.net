using System.Collections.Generic;
using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    public class OrganizationalPersonObjectClass : PersonObjectClass
    {
        public OrganizationalPersonObjectClass()
        {
            ObjectClass.Entries.Add("organizationalPerson");
        }

        public LocalityAttribute Locality { get; set; }

        protected override void GetAttributes(List<AbstractLdapAttribute> result)
        {
            result.Add(Locality);
            base.GetAttributes(result);
        }
    }
}
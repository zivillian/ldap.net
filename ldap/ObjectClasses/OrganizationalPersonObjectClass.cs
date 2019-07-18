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
        
        public OuAttribute OrganizationalUnitName { get; set; }

        protected override void GetAttributes(List<AbstractLdapAttribute> result)
        {
            result.Add(Locality);
            result.Add(OrganizationalUnitName);
            base.GetAttributes(result);
        }
    }
}
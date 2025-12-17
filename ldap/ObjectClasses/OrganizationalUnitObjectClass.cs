using System;
using System.Collections.Generic;
using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    public class OrganizationalUnitObjectClass:TopObjectClass
    {
        public OrganizationalUnitObjectClass()
        {
            ObjectClass.Entries.Add("organizationalUnit");
            Ou = new OuAttribute();
        }

        public OuAttribute Ou { get; }

        public DescriptionAttribute? Description { get; set; }
        
        public LocalityAttribute? Locality { get; set; }

        protected override void GetAttributes(List<AbstractLdapAttribute?> result)
        {
            result.Add(Ou);
            result.Add(Description);
            result.Add(Locality);

            base.GetAttributes(result);
        }
    }
}

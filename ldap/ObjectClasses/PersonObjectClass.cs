using System.Collections.Generic;
using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    public class PersonObjectClass : TopObjectClass
    {
        public PersonObjectClass()
        {
            ObjectClass.Entries.Add("person");
            Sn = new SnAttribute();
            Cn = new CnAttribute();

        }
        public SnAttribute Sn { get; }

        public CnAttribute Cn { get; }

        public TelephoneNumberAttribute TelephoneNumber  { get; set; }

        public DescriptionAttribute Description { get; set; }

        protected override void GetAttributes(List<AbstractLdapAttribute> result)
        {
            result.Add(Sn);
            result.Add(Cn);
            result.Add(TelephoneNumber);
            result.Add(Description);
            base.GetAttributes(result);
        }
    }
}
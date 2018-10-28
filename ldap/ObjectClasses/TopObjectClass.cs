using System;
using System.Collections.Generic;
using System.Linq;
using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    public abstract class TopObjectClass
    {
        protected TopObjectClass()
        {
            ObjectClass = new ObjectClassAttribute();
            ObjectClass.Entries.Add("top");
        }

        public ObjectClassAttribute ObjectClass { get; }

        public LdapAttribute[] GetAttributes(LdapAttributeSelection[] selection, bool typesOnly)
        {
            if (selection.Length == 1 && selection[0].NoAttributes)
                return new LdapAttribute[0];

            var attributes = GetAttributes();
            if (selection.Length == 0)
            {
                attributes = attributes.Where(x => x.Usage == LdapAttributeTypeUsage.UserApplication);
            }
            else
            {
                var selectors = selection
                    .Where(x => !x.AllUserAttributes)
                    .Where(x => !x.NoAttributes)
                    .Select(x => x.Selector)
                    .ToList();

                if (selection.Any(x => x.AllUserAttributes))
                {
                    attributes = attributes
                        .Where(x => selectors.Any(x.IsType) || x.Usage == LdapAttributeTypeUsage.UserApplication);
                }
                else
                {
                    attributes = attributes.Where(x => selectors.Any(x.IsType));
                }
            }
            if (typesOnly)
            {
                return attributes.Select(x => new LdapAttribute(x.Type, new ReadOnlyMemory<byte>[0])).ToArray();
            }
            return attributes.ToArray();
        }

        public IEnumerable<AbstractLdapAttribute> GetAttributes()
        {
            var attributes = new List<AbstractLdapAttribute>();
            GetAttributes(attributes);
            return attributes.Where(x=>x != null).Where(x=>x.HasValue);
        }

        protected virtual void GetAttributes(List<AbstractLdapAttribute> result)
        {
            result.Add(ObjectClass);
        }
    }
}
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

        public LdapDistinguishedName Parent { get; set; }

        public ObjectClassAttribute ObjectClass { get; }

        public CreatorsNameAttribute CreatorsName { get; set; }

        public CreateTimestampAttribute CreateTimestamp { get; set; }

        public ModifiersNameAttribute ModifiersName { get; set; }

        public ModifyTimestampAttribute ModifyTimestamp { get; set; }

        public ICollection<LdapAttribute> GetAttributes(IReadOnlyList<LdapAttributeSelection> selection, bool typesOnly)
        {
            if (selection.Count == 1 && selection[0].NoAttributes)
                return new List<LdapAttribute>();

            var attributes = GetAttributes();
            if (selection.Count == 0)
            {
                attributes = attributes.Where(x => x.Usage == LdapAttributeTypeUsage.UserApplication);
            }
            else
            {
                var selectors = selection
                    .Where(x => !x.AllUserAttributes)
                    .Where(x => !x.NoAttributes)
                    .Where(x => !x.AllOperationalAttributes)
                    .Select(x => x.Selector)
                    .ToList();

                if (selection.Any(x => x.AllUserAttributes))
                {
                    if (!selection.Any(x => x.AllOperationalAttributes))
                    {
                        attributes = attributes
                            .Where(x => selectors.Any(x.IsType) || x.Usage == LdapAttributeTypeUsage.UserApplication);
                    }
                }
                else
                {
                    if (selection.Any(x => x.AllOperationalAttributes))
                    {
                        attributes = attributes.Where(x => selectors.Any(x.IsType) || x.Usage != LdapAttributeTypeUsage.UserApplication);
                    }
                    else
                    {
                        attributes = attributes.Where(x => selectors.Any(x.IsType));
                    }
                }
            }
            if (typesOnly)
            {
                return attributes.Select(x => new LdapAttribute(x.Type, Array.Empty<ReadOnlyMemory<byte>>())).ToList();
            }
            return attributes.ToList<LdapAttribute>();
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
            result.Add(CreatorsName);
            result.Add(CreateTimestamp);
            result.Add(ModifiersName);
            result.Add(ModifyTimestamp);
        }
    }
}
using System;
using System.Diagnostics.CodeAnalysis;

namespace zivillian.ldap
{
    public class LdapAttributeSelection
    {
        public bool AllUserAttributes { get; }

        public bool NoAttributes { get; }

        public bool AllOperationalAttributes { get; }

        public LdapAttributeDescription? Selector { get; }

        public LdapAttributeSelection(ReadOnlySpan<byte> data)
            :this(data.LdapString())
        {
        }

        public LdapAttributeSelection(ReadOnlySpan<char> data)
        {
            if (data.Length == 1 && data[0] == '*')
            {
                AllUserAttributes = true;
            }
            else if (data.Length == 3 && data is "1.1")
            {
                NoAttributes = true;
            }
            else if (data.Length == 1 && data[0] == '+')
            {
                AllOperationalAttributes = true;
            }
            else 
            {
                Selector = new LdapAttributeDescription(data);
            }
        }

        public override string ToString()
        {
            if (AllUserAttributes)
                return "*";
            if (NoAttributes)
                return "1.1";
            if (AllOperationalAttributes)
                return "+";
            if (Selector is not null)
                return Selector.ToString();
            throw new InvalidOperationException("this cannot happen");
        }

        public ReadOnlyMemory<byte> GetBytes()
        {
            return ToString().LdapString();
        }
    }
}
using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSubstringFilter : LdapFilter
    {
        public LdapAttributeDescription Attribute { get; }

        public ReadOnlyMemory<byte>? StartsWith { get; }

        public ReadOnlyMemory<byte>? EndsWith { get; }

        public ReadOnlyMemory<byte>[] Contains { get; }

        internal LdapSubstringFilter(Asn1SubstringFilter filter)
        {
            Attribute = new LdapAttributeDescription(filter.Type.Span);
            var contains = new List<ReadOnlyMemory<byte>>();
            foreach (var substring in filter.Substrings)
            {
                if (substring.Initial.HasValue)
                {
                    StartsWith = substring.Initial.Value;
                }
                else if (substring.Final.HasValue)
                {
                    EndsWith = substring.Final.Value;
                }
                else if (substring.Any.HasValue)
                {
                    contains.Add(substring.Any.Value);
                }
            }
            Contains = contains.ToArray();
        }

        internal override Asn1Filter GetAsn()
        {
            var substrings = new List<Asn1Substring>();
            if (StartsWith != null)
                substrings.Add(new Asn1Substring{Initial = StartsWith});
            foreach (var substring in Contains)
            {
                substrings.Add(new Asn1Substring{Any = substring});
            }
            if (EndsWith != null)
                substrings.Add(new Asn1Substring{Final = EndsWith});

            return new Asn1Filter
            {
                Substrings = new Asn1SubstringFilter
                {
                    Type = Attribute.GetBytes(),
                    Substrings = substrings.ToArray()
                }
            };
        }

        public override string ToString()
        {
            if (Contains.Length == 0)
                return $"({StartsWith}*{EndsWith})";
            return $"({StartsWith}*{String.Join('*', Contains)}*{EndsWith})";
        }
    }
}
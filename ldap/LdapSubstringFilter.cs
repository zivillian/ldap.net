using System;
using System.Collections.Generic;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSubstringFilter : LdapFilter
    {
        public string Attribute { get; }

        public string StartsWith { get; }

        public string EndsWith { get; }

        public string[] Contains { get; }

        internal LdapSubstringFilter(Asn1SubstringFilter filter)
        {
            Attribute = Encoding.UTF8.GetString(filter.Type.Span);
            var contains = new List<string>();
            foreach (var substring in filter.Substrings)
            {
                if (substring.Initial.HasValue)
                {
                    StartsWith = Unescape(Encoding.UTF8.GetString(substring.Initial.Value.Span));
                }
                else if (substring.Final.HasValue)
                {
                    EndsWith = Unescape(Encoding.UTF8.GetString(substring.Final.Value.Span));
                }
                else if (substring.Any.HasValue)
                {
                    contains.Add(Unescape(Encoding.UTF8.GetString(substring.Any.Value.Span)));
                }
            }
            Contains = contains.ToArray();
        }

        internal override Asn1Filter GetAsn()
        {
            var substrings = new List<Asn1Substring>();
            if (StartsWith != null)
                substrings.Add(new Asn1Substring{Initial = Encoding.UTF8.GetBytes(Escape(StartsWith))});
            foreach (var substring in Contains)
            {
                substrings.Add(new Asn1Substring{Any = Encoding.UTF8.GetBytes(Escape(substring))});
            }
            if (EndsWith != null)
                substrings.Add(new Asn1Substring{Final = Encoding.UTF8.GetBytes(Escape(EndsWith))});

            return new Asn1Filter
            {
                Substrings = new Asn1SubstringFilter
                {
                    Type = Encoding.UTF8.GetBytes(Attribute),
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
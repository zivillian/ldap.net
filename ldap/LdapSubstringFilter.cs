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

        public IReadOnlyList<ReadOnlyMemory<byte>> Contains { get; }

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
            Contains = contains;
        }

        internal LdapSubstringFilter(ReadOnlySpan<char> description, ReadOnlyMemory<byte>? initial, ReadOnlyMemory<byte>[] any, ReadOnlyMemory<byte>? final)
        {
            if (!initial.HasValue && !final.HasValue && any.Length == 0)
                throw new ArgumentException("at least one part must be set");

            Attribute = new LdapAttributeDescription(description);
            StartsWith = initial;
            Contains = any;
            EndsWith = final;
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
            var initial = String.Empty;
            if (StartsWith.HasValue)
                initial = StartsWith.Value.Span.EscapeAssertionValue();
            var final = String.Empty;
            if (EndsWith.HasValue)
                final = EndsWith.Value.Span.EscapeAssertionValue();
            if (Contains.Count == 0)
                return $"({Attribute}={initial}*{final})";
            var any = new string[Contains.Count];
            for (int i = 0; i < Contains.Count; i++)
            {
                any[i] = Contains[i].Span.EscapeAssertionValue();
            }
            return $"({Attribute}={initial}*{String.Join('*', any)}*{final})";
        }
    }
}
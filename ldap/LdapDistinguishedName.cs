using System;
using System.Collections.Generic;

namespace zivillian.ldap
{
    //RFC 4514
    public class LdapDistinguishedName
    {
        public static readonly LdapDistinguishedName Empty = new LdapDistinguishedName(String.Empty);

        public IReadOnlyList<LdapRelativeDistinguishedName> RDNs { get; }

        public LdapDistinguishedName(string type, string value, LdapDistinguishedName parent)
        :this(new LdapRelativeDistinguishedName(new LdapAttributeTypeAndValue(type, value, false)), parent)
        {
        }

        public LdapDistinguishedName(LdapRelativeDistinguishedName rdn, LdapDistinguishedName parent)
        {
            var rdns = new LdapRelativeDistinguishedName[parent.RDNs.Count+1];
            rdns[0] = rdn;
            for (int i = 0; i < parent.RDNs.Count; i++)
            {
                rdns[i + 1] = parent.RDNs[i];
            }
            RDNs = rdns;
        }

        public LdapDistinguishedName(ReadOnlySpan<byte> data)
            : this(data.LdapString())
        {
        }

        public LdapDistinguishedName(ReadOnlySpan<char> dn)
        {
            if (dn.IsEmpty)
            {
                RDNs = Array.Empty<LdapRelativeDistinguishedName>();
                return;
            }
            var rdns = new List<LdapRelativeDistinguishedName>();
            int index;
            while ((index = dn.IndexOfUnescaped(',')) >= 0)
            {
                rdns.Add(new LdapRelativeDistinguishedName(dn.Slice(0, index)));
                dn = dn.Slice(index + 1);
            }
            rdns.Add(new LdapRelativeDistinguishedName(dn));
            RDNs = rdns.ToArray();
        }


        public override string ToString()
        {
            if (RDNs is null)
                return base.ToString();
            return String.Join<LdapRelativeDistinguishedName>(',', RDNs);
        }

        public ReadOnlyMemory<byte> GetBytes()
        {
            return ToString().LdapString();
        }
    }

    public class LdapRelativeDistinguishedName
    {
        public IReadOnlyList<LdapAttributeTypeAndValue> Values { get; }

        public LdapRelativeDistinguishedName(LdapAttributeTypeAndValue value)
        {
            Values = new[] {value};
        }

        public LdapRelativeDistinguishedName(ReadOnlySpan<char> rdn)
        {
            if (rdn.IsEmpty)
                throw new InvalidDnSyntaxException("invalid relativeDistinguishedName");
            var parts = new List<LdapAttributeTypeAndValue>();
            int index;
            while ((index = rdn.IndexOfUnescaped('+')) >= 0)
            {
                parts.Add(new LdapAttributeTypeAndValue(rdn.Slice(0, index)));
                rdn = rdn.Slice(index + 1);
            }
            parts.Add(new LdapAttributeTypeAndValue(rdn));
            Values = parts;
        }

        public override string ToString()
        {
            if (Values is null)
                return base.ToString();
            return String.Join<LdapAttributeTypeAndValue>('+', Values);
        }

        public ReadOnlyMemory<byte> GetBytes()
        {
            return ToString().LdapString();
        }
    }

    public class LdapAttributeTypeAndValue
    {
        //ci
        public string Type { get; }

        public string Value { get; }

        public bool IsHexstring { get; }

        public LdapAttributeTypeAndValue(string type, string value, bool isHex)
        {
            if (String.IsNullOrEmpty(type))
                throw new ArgumentNullException(nameof(type));

            if (value is null)
                throw new ArgumentNullException(nameof(value));

            Type = type;
            Value = value;
            IsHexstring = isHex;
        }

        public LdapAttributeTypeAndValue(ReadOnlySpan<char> typeAndValue)
        {
            var equals = typeAndValue.IndexOf('=');
            if (equals < 0)
                throw new InvalidDnSyntaxException("invalid attributeTypeAndValue");
            var type = typeAndValue.Slice(0, equals);
            if (type.TryParseNumericOid(out var numeridoid))
            {
                Type = numeridoid;
            }
            else if (type.TryParseKeystring(out var descr))
            {
                Type = descr;
            }
            else
            {
                throw new InvalidDnSyntaxException("invalid attributeType");
            }
            var value = typeAndValue.Slice(equals + 1);
            if (value.TryParseHexstring(out var hexstring))
            {
                IsHexstring = true;
                Value = hexstring;
            }
            else if (value.TryUnescapeString(out var unescaped))
            {
                Value = unescaped;
            }
            else
            {
                throw new InvalidDnSyntaxException("invalid attributeValue");
            }
        }

        public override string ToString()
        {
            if (Type is null || Value is null)
                return base.ToString();
            if (IsHexstring)
                return $"{Type}={Value}";
            return $"{Type}={Value.AsSpan().EscapeString()}";
        }
    }
}
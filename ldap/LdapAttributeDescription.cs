using System;
using System.Collections.Generic;
using System.Reflection.Metadata.Ecma335;

namespace zivillian.ldap
{
    public class LdapAttributeDescription
    {
        public string Oid { get; }

        public string[] Options { get; }

        public LdapAttributeDescription(ReadOnlySpan<byte> data)
        :this(data.LdapString())
        {
        }

        public LdapAttributeDescription(ReadOnlySpan<char> data)
        {
            var index = data.IndexOf(';');
            if (index < 0)
            {
                Oid = data.Oid();
                Options = new string[0];
            }
            else
            {
                Oid = data.Slice(0, index).Oid();
                data = data.Slice(index + 1);
                var options = new List<string>();
                while ((index = data.IndexOf(';')) >= 0)
                {
                    if (!data.Slice(0, index).TryParseKeychar(out var option))
                        throw new LdapProtocolException("invalid option");
                    options.Add(option);
                    data = data.Slice(index + 1);
                } 

                if (!data.TryParseKeychar(out var last))
                    throw new LdapProtocolException("invalid option");
                options.Add(last);
                Options = options.ToArray();
            }
        }

        public override string ToString()
        {
            if (Oid is null || Options is null)
                return base.ToString();
            if (Options.Length == 0)
                return Oid;
            return $"{Oid};{String.Join(';', Options)}";
        }

        public ReadOnlyMemory<byte> GetBytes()
        {
            return ToString().LdapString();
        }
    }
}
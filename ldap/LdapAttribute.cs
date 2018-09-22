using System;
using System.IO;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapAttribute
    {
        public string Type { get; }

        public string[] Values { get; }

        internal LdapAttribute(Asn1PartialAttribute attribute)
        {
            Type = Encoding.UTF8.GetString(attribute.Type.Span);
            Values= new string[0];
            if (attribute.Values.Length > 0)
            {
                Values = new string[attribute.Values.Length];
                for (int i = 0; i < attribute.Values.Length; i++)
                {
                    Values[i] = Encoding.UTF8.GetString(attribute.Values[i].Span);
                }
            }
        }

        internal Asn1PartialAttribute GetAsn()
        {
            var result = new Asn1PartialAttribute
            {
                Type = Encoding.UTF8.GetBytes(Type),
                Values = new ReadOnlyMemory<byte>[0]
            };
            if (Values != null && Values.Length > 0)
            {
                result.Values = new ReadOnlyMemory<byte>[Values.Length];
                for (int i = 0; i < Values.Length; i++)
                {
                    result.Values[i] = Encoding.UTF8.GetBytes(Values[i]);
                }
            }
            return result;
        }
    }
}
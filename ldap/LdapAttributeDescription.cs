using System;
using System.Collections.Generic;

namespace zivillian.ldap
{
    public class LdapAttributeDescription
    {
        public string Oid { get; }

        public string[] Options { get; }

        public LdapAttributeDescription(ReadOnlyMemory<byte> data)
        {
            var span = data.Span;
            var index = span.IndexOf((byte) ';');
            throw new NotImplementedException();
            //Oid = span.Slice(0, index).Oid();
            //span = span.Slice(index + 1);
            //if (span.IsEmpty) return;
            //var options = new List<string>();
            //while ((index = span.IndexOf((byte)';')) >= 0)
            //{
            //    if (index == 0)
            //        throw new ArgumentException("invalid empty option");
            //    options.Add(span.Slice(0, index).ParseKeychar());
            //}
            //Options = options.ToArray();
        }

        public ReadOnlyMemory<byte> GetBytes()
        {
            if (Options == null || Options.Length == 0)
            {
                throw new NotImplementedException();
            }
            throw new NotImplementedException();
        }
    }
}
using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchRequest : LdapRequestMessage
    {
        public string BaseObject { get; }

        public SearchScope Scope { get; }

        public DerefAliases DerefAliases { get; }

        public int SizeLimit { get; }

        public TimeSpan TimeLimit { get; }

        public bool TypesOnly { get; }

        internal LdapSearchRequest(Asn1LdapMessage message)
            : base(message)
        {
            var search = message.ProtocolOp.SearchRequest;
            BaseObject = Encoding.UTF8.GetString(search.BaseObject.Span);
            Scope = search.Scope;
            DerefAliases = search.DerefAliases;
            SizeLimit = search.SizeLimit;
            if (SizeLimit == 0)
                SizeLimit = Int32.MaxValue;
            TimeLimit = TimeSpan.FromSeconds(search.TimeLimit);
            if (TimeLimit == TimeSpan.Zero)
                TimeLimit = TimeSpan.MaxValue;
            TypesOnly = search.TypesOnly;
            //TODO search.Filter
            //TODO search.Attributes
        }
    }
}
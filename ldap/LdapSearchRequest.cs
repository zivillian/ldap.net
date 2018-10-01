using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapSearchRequest : LdapRequestMessage
    {
        public LdapDistinguishedName BaseObject { get; }

        public SearchScope Scope { get; }

        public DerefAliases DerefAliases { get; }

        public int SizeLimit { get; }

        public TimeSpan TimeLimit { get; }

        public bool TypesOnly { get; }

        public LdapFilter Filter { get; }

        public LdapAttributeSelection[] Attributes { get; }

        internal LdapSearchRequest(Asn1LdapMessage message)
            : base(message)
        {
            var search = message.ProtocolOp.SearchRequest;
            BaseObject = new LdapDistinguishedName(search.BaseObject.Span);
            Scope = search.Scope;
            DerefAliases = search.DerefAliases;
            if (DerefAliases < DerefAliases.NeverDerefAliases || DerefAliases > DerefAliases.DerefAlways)
                throw new LdapProtocolException("invalid derefAliases");
            SizeLimit = search.SizeLimit;
            if (SizeLimit == 0)
                SizeLimit = Int32.MaxValue;
            else if (SizeLimit < 0)
                throw new LdapProtocolException("invalid sizeLimit");
            TimeLimit = TimeSpan.FromSeconds(search.TimeLimit);
            if (TimeLimit == TimeSpan.Zero)
                TimeLimit = TimeSpan.MaxValue;
            else if (TimeLimit < TimeSpan.Zero)
                throw new LdapProtocolException("invalid timeLimit");
            TypesOnly = search.TypesOnly;
            Filter = LdapFilter.Create(search.Filter);
            Attributes = new LdapAttributeSelection[0];
            if (search.Attributes.Length > 0)
            {
                Attributes = new LdapAttributeSelection[search.Attributes.Length];
                for (int i = 0; i < search.Attributes.Length; i++)
                {
                    Attributes[i] = new LdapAttributeSelection(search.Attributes[i].Span);
                }
            }
        }

        internal LdapSearchRequest(int messageId, string baseDn, SearchScope scope, string filter, string[] attributes, bool attributesOnly, TimeSpan timeout, int sizeLimit, LdapControl[] controls)
            : base(messageId, controls)
        {
            if (timeout < TimeSpan.Zero)
                throw new LdapProtocolException("invalid timeLimit");
            if (sizeLimit < 0)
                throw new LdapProtocolException("invalid sizeLimit");
            BaseObject = new LdapDistinguishedName(baseDn);
            Scope = scope;
            Filter = LdapFilter.Parse(filter);
            if (attributes != null && attributes.Length > 0)
            {
                Attributes = new LdapAttributeSelection[attributes.Length];
                for (int i = 0; i < attributes.Length; i++)
                {
                    Attributes[i] = new LdapAttributeSelection(attributes[i]);
                }
            }
            TypesOnly = attributesOnly;
            TimeLimit = timeout;
            SizeLimit = sizeLimit;
        }

        internal override void SetProtocolOp(Asn1ProtocolOp op)
        {
            op.SearchRequest = new Asn1SearchRequest
            {
                BaseObject =  BaseObject.GetBytes(),
                Scope = Scope,
                DerefAliases = DerefAliases,
                SizeLimit = SizeLimit,
                TimeLimit = (int) TimeLimit.TotalSeconds,
                TypesOnly = TypesOnly,
                Filter = Filter.GetAsn(),
                Attributes = new ReadOnlyMemory<byte>[0]
            };
            if (SizeLimit == Int32.MaxValue)
                op.SearchRequest.SizeLimit = 0;
            if (TimeLimit == TimeSpan.MaxValue)
                op.SearchRequest.TimeLimit = 0;
            if (Attributes != null && Attributes.Length > 0)
            {
                var attr = op.SearchRequest.Attributes = new ReadOnlyMemory<byte>[Attributes.Length];
                for (int i = 0; i < Attributes.Length; i++)
                {
                    attr[i] = Attributes[i].GetBytes();
                }
            }
        }
    }
}
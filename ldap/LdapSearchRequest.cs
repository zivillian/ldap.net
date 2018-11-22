using System;
using System.Collections.Generic;
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

        public IReadOnlyList<LdapAttributeSelection> Attributes { get; }

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
            if (TimeLimit < TimeSpan.Zero)
                throw new LdapProtocolException("invalid timeLimit");
            TypesOnly = search.TypesOnly;
            Filter = LdapFilter.Create(search.Filter);
            if (search.Attributes.Length > 0)
            {
                var attributes = new LdapAttributeSelection[search.Attributes.Length];
                for (int i = 0; i < search.Attributes.Length; i++)
                {
                    attributes[i] = new LdapAttributeSelection(search.Attributes[i].Span);
                }
                Attributes = attributes;
            }
            else
            {
                Attributes = Array.Empty<LdapAttributeSelection>();
            }
        }

        public LdapSearchRequest(int messageId, string baseDn, SearchScope scope, string filter, string[] attributes, bool attributesOnly, TimeSpan timeout, int sizeLimit, LdapControl[] controls)
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
                var ldapAttributes = new LdapAttributeSelection[attributes.Length];
                for (int i = 0; i < attributes.Length; i++)
                {
                    ldapAttributes[i] = new LdapAttributeSelection(attributes[i]);
                }
                Attributes = ldapAttributes;
            }
            else
            {
                Attributes = Array.Empty<LdapAttributeSelection>();
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
                TimeLimit = (int) TimeLimit.TotalSeconds,
                TypesOnly = TypesOnly,
                Filter = Filter.GetAsn(),
            };

            if (SizeLimit == Int32.MaxValue)
                op.SearchRequest.SizeLimit = 0;
            else
                op.SearchRequest.SizeLimit = SizeLimit;
            
            if (Attributes != null && Attributes.Count > 0)
            {
                var attr = op.SearchRequest.Attributes = new ReadOnlyMemory<byte>[Attributes.Count];
                for (int i = 0; i < Attributes.Count; i++)
                {
                    attr[i] = Attributes[i].GetBytes();
                }
            }
            else
            {
                op.SearchRequest.Attributes = Array.Empty<ReadOnlyMemory<byte>>();
            }
        }

        public LdapSearchResultEntry Result(LdapDistinguishedName objectName, LdapAttribute[] attributes, LdapControl[] controls)
        {
            return new LdapSearchResultEntry(Id, objectName, attributes, controls);
        }

        public LdapSearchResultDone Done(ResultCode resultCode = ResultCode.Success)
        {
            return Done(resultCode, Array.Empty<string>());
        }

        public LdapSearchResultDone Done(ResultCode resultCode, string[] referrals)
        {
            return new LdapSearchResultDone(Id, resultCode, LdapDistinguishedName.Empty, String.Empty, referrals, Array.Empty<LdapControl>());
        }
    }
}
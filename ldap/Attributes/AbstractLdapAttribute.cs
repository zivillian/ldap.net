using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection.Metadata;
using System.Text;

namespace zivillian.ldap.Attributes
{
    public abstract class AbstractLdapAttribute: LdapAttribute
    {
        protected AbstractLdapAttribute(ReadOnlySpan<char> type) 
            : base(type, Array.Empty<ReadOnlyMemory<byte>>())
        {
        }

        public abstract string Oid { get; }

        public virtual string Name { get; }

        public abstract LdapAttributeTypeUsage Usage { get; }

        public abstract bool HasValue { get; }

        public bool IsType(LdapAttributeDescription type)
        {
            return String.Equals(Name, type.Oid, StringComparison.OrdinalIgnoreCase) ||
                   String.Equals(Oid, type.Oid, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// 1.3.6.1.4.1.1466.115.121.1.38
    /// </summary>
    public abstract class OidSyntaxLdapAttribute : AbstractLdapAttribute<string>
    {
        protected OidSyntaxLdapAttribute(string nameOrOid) : base(nameOrOid)
        {
        }

        protected override ReadOnlyMemory<byte> Serialize(string entry)
        {
            return entry.AsSpan().Oid().LdapString();
        }

    }

    /// <summary>
    /// 1.3.6.1.4.1.1466.115.121.1.15
    /// </summary>
    public abstract class DirectoryStringSyntaxLdapAttribute : AbstractLdapAttribute<string>
    {
        protected DirectoryStringSyntaxLdapAttribute(string nameOrOid) : base(nameOrOid)
        {
        }
        protected override ReadOnlyMemory<byte> Serialize(string entry)
        {
            if (String.IsNullOrEmpty(entry))
                throw new ArgumentOutOfRangeException(nameof(entry), "empty value is not allowed");
            return entry.LdapString();
        }

    }

    /// <summary>
    /// 1.3.6.1.4.1.1466.115.121.1.15
    /// </summary>
    public abstract class IA5StringSyntaxLdapAttribute : AbstractLdapAttribute<string>
    {
        protected IA5StringSyntaxLdapAttribute(string nameOrOid) : base(nameOrOid)
        {
        }
        protected override ReadOnlyMemory<byte> Serialize(string entry)
        {
            return Encoding.ASCII.GetBytes(entry);
        }

    }
    
    /// <summary>
    /// 1.3.6.1.4.1.1466.115.121.1.44
    /// </summary>
    public abstract class PrintableStringLdapAttribute : AbstractLdapAttribute<string>
    {
        protected PrintableStringLdapAttribute(string nameOrOid):base(nameOrOid)
        {
        }

        protected override ReadOnlyMemory<byte> Serialize(string entry)
        {
            return Encoding.ASCII.GetBytes(entry);
        }
    }

    /// <summary>
    /// 1.3.6.1.4.1.1466.115.121.1.12
    /// </summary>
    public abstract class DNLdapAttribute : AbstractLdapAttribute<LdapDistinguishedName>
    {
        protected DNLdapAttribute(string nameOrOid) : base(nameOrOid)
        {
        }

        protected override ReadOnlyMemory<byte> Serialize(LdapDistinguishedName entry)
        {
            return entry.GetBytes();
        }
    }

    /// <summary>
    /// 1.3.6.1.4.1.1466.115.121.1.24
    /// </summary>
    public abstract class GeneralizedTimeAttribute : AbstractLdapAttribute<DateTimeOffset>
    {
        protected GeneralizedTimeAttribute(string nameOrOid) : base(nameOrOid)
        {
        }

        protected override ReadOnlyMemory<byte> Serialize(DateTimeOffset entry)
        {
            var value = entry.ToUniversalTime().ToString("yyyyMMddHHmmss\\Z", CultureInfo.InvariantCulture);
            return Encoding.ASCII.GetBytes(value);
        }
    }

    public abstract class AbstractLdapAttribute<T> : AbstractLdapAttribute
    {
        protected AbstractLdapAttribute(string nameOrOid)
            :base(nameOrOid)
        {
            Entries = new List<T>();
        }

        public override IReadOnlyList<ReadOnlyMemory<byte>> Values
        {
            get
            {
                var entries = Entries;
                var result = new ReadOnlyMemory<byte>[entries.Count];

                for (int i = 0; i < entries.Count; i++)
                {
                    result[i] = Serialize(entries[i]);
                }

                return result;
            }
        }

        protected abstract ReadOnlyMemory<byte> Serialize(T entry);

        public virtual List<T> Entries { get; }

        public override bool HasValue
        {
            get { return Entries.Count > 0; }
        }
    }
}
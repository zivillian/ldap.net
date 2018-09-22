using System;
using System.Globalization;
using System.Linq;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public abstract class LdapFilter
    {
        internal static LdapFilter Create(Asn1Filter filter)
        {
            if (filter.And != null)
            {
                return new LdapAndFilter(filter.And);
            }
            else if (filter.Or != null)
            {
                return new LdapOrFilter(filter.Or);
            }
            else if (filter.Not != null)
            {
                return new LdapNotFilter(filter.Not);
            }
            else if (filter.EqualityMatch != null)
            {
                return new LdapEqualityFilter(filter.EqualityMatch);
            }
            else if (filter.Substrings != null)
            {
                return new LdapSubstringFilter(filter.Substrings);
            }
            else if (filter.GreaterOrEqual != null)
            {
                return new LdapGreaterOrEqualFilter(filter.GreaterOrEqual);
            }
            else if (filter.LessOrEqual != null)
            {
                return new LdapLessOrEqualFilter(filter.LessOrEqual);
            }
            else if (filter.Present.HasValue)
            {
                return new LdapPresentFilter(filter.Present.Value);
            }
            else if (filter.ApproxMatch != null)
            {
                return new LdapApproxMatchFilter(filter.ApproxMatch);
            }
            else if (filter.ExtensibleMatch != null)
            {
                return new LdapExtensibleMatchFilter(filter.ExtensibleMatch);
            }
            else
            {
                throw new NotImplementedException();
            }
        }
        
        private static readonly char[] _escapeChars = new[] {'\\', '*', '(', ')', '\0'};

        protected static string Escape(string value)
        {
            if (value.IndexOfAny(_escapeChars) < 0) return value;

            var span = value.AsSpan();
            var result = new StringBuilder();
            int index;
            while ((index = span.IndexOfAny(_escapeChars)) >= 0)
            {
                result.Append(span.Slice(0, index));
                result.Append('\\');
                result.Append(((int)span[index]).ToString("x2"));
                span = span.Slice(index + 1);
            }
            result.Append(span);
            return result.ToString();
        }

        protected static string Unescape(string value)
        {
            var index = value.IndexOf('\\');
            if (index < 0) return value;
            var span = value.AsSpan();
            var result = new StringBuilder();
            do
            {
                result.Append(span.Slice(0, index));
                if (!Int32.TryParse(span.Slice(index + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var hex))
                    throw new ArgumentException($"Invalid encoding of '{value}'");
                result.Append((char) hex);
                if (span.Length >= 3)
                    span = span.Slice(index + 3);
            } while ((index = span.IndexOf('\\')) >= 0);
            result.Append(span);
            return result.ToString();
        }

        internal virtual Asn1Filter GetAsn()
        {
            throw new NotImplementedException();
        }

        public abstract override string ToString();
    }
}
using System;
using System.Collections.Generic;
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

        public static LdapFilter Parse(ReadOnlySpan<char> filter)
        {
            if (filter.Length < 2)
                throw new LdapFilterParseException("invalid filter");
            if (filter[0] != '(')
                throw new LdapFilterParseException("missing parenthesis");
            if (filter[filter.Length-1] != ')')
                throw new LdapFilterParseException("missing parenthesis");

            filter = filter.Slice(1, filter.Length - 2);

            switch (filter[0])
            {
                case '&':
                    return ParseAnd(filter.Slice(1));
                case '|':
                    return ParseOr(filter.Slice(1));
                case '!':
                    return new LdapNotFilter(Parse(filter.Slice(1)));
            }
            int index;
            if (filter.EndsWith("=*"))
            {
                throw new NotImplementedException("present");
            }
            else if ((index = filter.IndexOf('=')) >= 0)
            {
                var assertion = filter.Slice(index + 1);
                if (assertion.IndexOf('*') >= 0)
                {
                    var attr = filter.Slice(0, index);
                    return ParseSubstring(attr, assertion);
                }
                else if (index > 0 && filter[index - 1] == '~')
                {
                    throw new NotImplementedException("approx");
                }
                else if (index > 0 && filter[index - 1] == '>')
                {
                    throw new NotImplementedException("greaterorequal");
                }
                else if (index > 0 && filter[index - 1] == '<')
                {
                    throw new NotImplementedException("lessorequal");
                }
                else if (index > 0 && filter[index - 1] == ':')
                {
                    var attr = filter.Slice(0, index-1);
                    return ParseExtensible(attr, assertion);
                }
                else
                {
                    var attr = filter.Slice(0, index);
                    return new LdapEqualityFilter(new LdapAttributeAssertion(attr, assertion));
                }
            }
            throw new LdapProtocolException("invalid filter syntax");
        }

        internal static LdapExtensibleMatchFilter ParseExtensible(ReadOnlySpan<char> description, ReadOnlySpan<char> assertion)
        {
            var colon = description.IndexOf(':');
            bool isDn = false;
            ReadOnlySpan<char> matchingRule;
            if (colon >= 0)
            {
                matchingRule = description.Slice(colon + 1);
                description = description.Slice(0, colon);
                if ((colon = matchingRule.IndexOf(':')) >= 0)
                {
                    if (colon != 2 || (matchingRule[0] != 'd' && matchingRule[0] != 'D')  || (matchingRule[1] != 'n' && matchingRule[1] != 'N'))
                    {
                        throw new LdapFilterParseException("invalid dnattrs");
                    }
                    else
                    {
                        isDn = true;
                    }
                    matchingRule = matchingRule.Slice(colon + 1);
                }
            }
            else
            {
                matchingRule = ReadOnlySpan<char>.Empty;
            }
            return new LdapExtensibleMatchFilter(description, isDn, matchingRule, assertion);
        }

        internal static LdapSubstringFilter ParseSubstring(ReadOnlySpan<char> description, ReadOnlySpan<char> assertion)
        {
            ReadOnlyMemory<byte>? initial = null;
            var index = assertion.IndexOf('*');
            if (index > 0)
            {
                initial = assertion.Slice(0, index).UnescapeString().LdapString();
            }
            assertion = assertion.Slice(index + 1);
            index = assertion.IndexOf('*');
            List<ReadOnlyMemory<byte>> any = new List<ReadOnlyMemory<byte>>();
            while (index > 0)
            {
                any.Add(assertion.Slice(0, index).UnescapeString().LdapString());
                assertion = assertion.Slice(index + 1);
                index = assertion.IndexOf('*');
            }
            ReadOnlyMemory<byte>? final = null;
            if (!assertion.IsEmpty)
            {
                final = assertion.UnescapeString().LdapString();
            }
            return new LdapSubstringFilter(description, initial, any.ToArray(), final);
        }

        internal static LdapAndFilter ParseAnd(ReadOnlySpan<char> inner)
        {
            return new LdapAndFilter(ParseChildren(inner));
        }

        internal static LdapOrFilter ParseOr(ReadOnlySpan<char> inner)
        {
            return new LdapOrFilter(ParseChildren(inner));
        }

        internal static LdapFilter[] ParseChildren(ReadOnlySpan<char> inner)
        {
            var children = new List<LdapFilter>();
            var state = 0;
            var start = 0;
            var end = inner.IndexOfAny('(', ')');
            while (inner.Length > 0)
            {
                if (inner[end] == ')')
                {
                    state--;
                    if (state == 0)
                    {
                        end++;
                        children.Add(Parse(inner.Slice(0, end)));
                        inner = inner.Slice(end);
                        if (inner.IsEmpty)
                            break;
                        end = -1;
                    }
                }
                else
                {
                    state++;
                }
                end++;
                var next = inner.Slice(end).IndexOfAny('(', ')');
                if (next < 0)
                    throw new LdapFilterParseException("missing parenthesis");
                end += next;
            }

            if (!inner.IsEmpty)
                throw new LdapFilterParseException("missing parenthesis");
            return children.ToArray();
        }

        internal abstract Asn1Filter GetAsn();

        public abstract override string ToString();
    }
}
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace zivillian.ldap
{
    internal static class OctectStringExtensions
    {
        public static string Keystring(this ReadOnlySpan<byte> data)
        {
            if (!data.TryParseKeystring(out var keystring))
                throw new ArgumentException("invalid keystring");
            return keystring;
        }

        public static bool TryParseKeystring(this ReadOnlySpan<byte> data, [NotNullWhen(true)] out string? keystring)
        {
            //keystring = leadkeychar *keychar
            //leadkeychar = ALPHA
            keystring = null;
            if (data.IsEmpty)
                return false;
            if ((data[0] < 0x41 || data[0] > 0x5a) && (data[0] < 0x61 && data[0] > 0x7a))
                return false;
            return TryParseKeychar(data, out keystring);
        }

        public static bool TryParseKeystring(this ReadOnlySpan<char> data, [NotNullWhen(true)] out string? keystring)
        {
            //keystring = leadkeychar *keychar
            //leadkeychar = ALPHA
            keystring = null;
            if (data.IsEmpty)
                return false;
            if ((data[0] < 0x41 || data[0] > 0x5a) && (data[0] < 0x61 || data[0] > 0x7a))
                return false;
            return TryParseKeychar(data, out keystring);
        }

        public static string ParseKeychar(this ReadOnlySpan<byte> data)
        {
            if (!TryParseKeychar(data, out var result))
                throw new ArgumentException("invalid keychar");
            return result;
        }

        public static bool TryParseKeychar(this ReadOnlySpan<byte> data, [NotNullWhen(true)] out string? keychar)
        {
            //keychar = ALPHA / DIGIT / HYPHEN
            keychar = null;
            if (data.IsEmpty)
                return false;
            for (int i = 0; i < data.Length; i++)
            {
                if ((data[i] < 0x41 || data[i] > 0x5a) && (data[i] < 0x61 || data[i] > 0x7a) && (data[i] < 0x30 || data[i] > 0x39) && (data[i] != 0x2d))
                    return false;
            }
            keychar = Encoding.ASCII.GetString(data);
            return true;
        }

        public static bool TryParseKeychar(this ReadOnlySpan<char> data, [NotNullWhen(true)] out string? keychar)
        {
            //keychar = ALPHA / DIGIT / HYPHEN
            keychar = null;
            if (data.IsEmpty)
                return false;
            for (int i = 0; i < data.Length; i++)
            {
                if ((data[i] < 0x41 || data[i] > 0x5a) && (data[i] < 0x61 || data[i] > 0x7a) && (data[i] < 0x30 || data[i] > 0x39) && (data[i] != 0x2d))
                    return false;
            }
            keychar = new string(data);
            return true;
        }

        public static string LdapString(this ReadOnlySpan<byte> data)
        {
            //LDAPString ::= OCTET STRING -- UTF-8 encoded
            return Encoding.UTF8.GetString(data);
        }

        public static ReadOnlyMemory<byte> LdapString(this ReadOnlySpan<char> ldapstring)
        {
            return Encoding.UTF8.GetBytes(ldapstring.ToArray());
        }

        public static ReadOnlyMemory<byte> LdapString(this string ldapstring)
        {
            return Encoding.UTF8.GetBytes(ldapstring);
        }

        public static bool TryParseNumericOid(this ReadOnlySpan<byte> data, [NotNullWhen(true)] out string? numericoid)
        {
            //numericoid = number 1*( DOT number )
            numericoid = null;
            if (data.IsEmpty)
                return false;
            if (data[0] < 0x30 || data[0] > 0x39)
                return false;
            for (int i = 1; i < data.Length; i++)
            {
                if (data[i] != 0x2e && (data[i] < 0x30 || data[i] > 0x39))
                    return false;
            }
            numericoid = Encoding.ASCII.GetString(data);
            return true;
        }

        public static bool TryParseNumericOid(this ReadOnlySpan<char> data, [NotNullWhen(true)] out string? numericoid)
        {
            //numericoid = number 1*( DOT number )
            numericoid = null;
            if (data.IsEmpty)
                return false;
            if (data[0] < 0x30 || data[0] > 0x39)
                return false;
            for (int i = 1; i < data.Length; i++)
            {
                if (data[i] != 0x2e && (data[i] < 0x30 || data[i] > 0x39))
                    return false;
            }
            numericoid = new string(data);
            return true;
        }

        public static string NumericOid(this ReadOnlySpan<byte> data)
        {
            if (!data.TryParseNumericOid(out var numericoid))
                throw new ArgumentException("invalid ldapoip");
            return numericoid;
        }

        public static ReadOnlyMemory<byte> NumericOid(this string numericoid)
        {
            return Encoding.ASCII.GetBytes(numericoid);
        }

        public static bool TryParseHexstring(this ReadOnlySpan<char> data, [NotNullWhen(true)] out string? hexstring)
        {
            //hexstring = SHARP 1*hexpair
            //hexpair = HEX HEX
            //HEX     = DIGIT / %x41-46 / %x61-66 ; "0"-"9" / "A"-"F" / "a"-"f"
            hexstring = null;
            if (data.IsEmpty)
                return false;
            if (data[0] != '#')
                return false;
            if (data.Length < 3 || (data.Length % 2) == 0)
                return false;
            for (int i = 1; i < data.Length; i++)
            {
                if ((data[i] < 0x30 || data[i] > 0x39) && (data[i] < 0x41 || data[i] > 0x46) &&
                    (data[i] < 0x61 || data[i] > 0x66))
                    return false;
            }
            hexstring = new string(data);
            return true;
        }

        public static bool TryParseHexpair(this ReadOnlySpan<char> data, out byte value)
        {
            value = 0;
            if (data.Length != 2)
                return false;
            if (!Int32.TryParse(data, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var number))
            {
                return false;
            }
            value = (byte) number;
            return true;
        }

        private static readonly char[] _escaped = new[]
        {
            //escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
            '"', '+', ',', ';', '(', ')',
            //special = escaped / SPACE / SHARP / EQUALS
            ' ', '#', '='
        };
        
        public static bool TryUnescapeString(this ReadOnlySpan<char> data, [NotNullWhen(true)] out string? unescaped)
        {
            //todo handle multi byte hex
            unescaped = null;
            var result = new StringBuilder();
            int index;
            var escaped = _escaped.AsSpan();
            while ((index = data.IndexOf('\\')) >= 0)
            {
                result.Append(data.Slice(0, index));
                data = data.Slice(index + 1);
                if (data.IsEmpty)
                    return false;
                if (data[0] == '\\')
                {
                    result.Append('\\');
                    data = data.Slice(1);
                }
                else
                {
                    if (escaped.IndexOf(data[0]) >= 0)
                    {
                        result.Append(data[0]);
                        data = data.Slice(1);
                    }
                    else if (data.Length >= 2)
                    {
                        var bytes = new List<byte>();
                        while (data.Slice(0, 2).TryParseHexpair(out var value))
                        {
                            bytes.Add(value);
                            if (data.Length >= 5 && data[2] == '\\')
                            {
                                data = data.Slice(3);
                            }
                            else
                            {
                                data = data.Slice(2);
                                break;
                            }
                        }
                        if (bytes.Count == 0)
                            return false;
                        result.Append(Encoding.UTF8.GetString(bytes.ToArray()));
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            result.Append(data);
            unescaped = result.ToString();
            return true;
        }

        public static string UnescapeString(this ReadOnlySpan<char> data)
        {
            if (!data.TryUnescapeString(out var unescaped))
                throw new LdapException(ResultCode.InvalidAttributeSyntax, "invalid escaping");
            return unescaped;
        }

        public static string EscapeString(this ReadOnlySpan<char> text)
        {
            if (text.IsEmpty) return String.Empty;
            var result = new StringBuilder();
            if (text[0] == ' ' || text[0] == '#')
            {
                result.Append('\\');
                text = text.Slice(1);
            }
            var toEscape = new char[]
            {
                //The following characters are to be escaped when they appear
                //in the value to be encoded: ESC, one of <escaped>, leading
                //SHARP or SPACE, trailing SPACE, and NULL.
                '\\', '"', '+', ',', ';', '(', ')', '\0'
            };
            int index;
            while ((index = text.IndexOfAny(toEscape)) >= 0)
            {
                result.Append(text.Slice(0, index));
                if (text[index] == '\0')
                {
                    result.Append("\\00");
                }
                else
                {
                    result.Append('\\');
                    result.Append(text[index]);
                }
                text = text.Slice(index + 1);
            }
            result.Append(text);
            if (result[result.Length-1] == ' ')
            {
                result.Insert(result.Length-1, '\\');
            }
            return result.ToString();
        }

        public static int IndexOfUnescaped(this ReadOnlySpan<char> data, char c)
        {
            var index = data.IndexOf(c);
            if (index <= 0) return index;
            int offset = 0;
            while (index > 0 && data[offset + index - 1] == '\\')
            {
                index++;
                offset += index;
                index = data.Slice(offset).IndexOf(c);
            }
            if (index < 0)
                return index;
            return index + offset;
        }

        public static string Oid(this ReadOnlySpan<byte> data)
        {
            return Oid(data.LdapString());
        }

        public static string Oid(this ReadOnlySpan<char> data)
        {
            if (data.TryParseKeystring(out var keystring))
                return keystring;
            if (data.TryParseNumericOid(out var numericoid))
                return numericoid;
            throw new LdapProtocolException("invalid oid");
        }

        public static string EscapeAssertionValue(this ReadOnlySpan<byte> data)
        {
            return data.LdapString().AsSpan().EscapeAssertionValue();
        }
        
        private static readonly char[] AssertionValueEscaping = { '\0', '(', ')', '*', '\\'};

        public static string EscapeAssertionValue(this ReadOnlySpan<char> data)
        {
            var builder = new StringBuilder();
            int index;
            while ((index = data.IndexOfAny(AssertionValueEscaping)) >= 0)
            {
                builder.Append(data.Slice(0, index));
                builder.Append('\\');
                builder.Append(((int) data[index]).ToString("x2", CultureInfo.InvariantCulture));
                data = data.Slice(index + 1);
            }
            if (!data.IsEmpty)
                builder.Append(data);
            return builder.ToString();
        }
    }
}
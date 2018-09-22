using Xunit;

namespace zivillian.ldap.test
{
    public class EscapeTest
    {
        [Fact]
        public void DoesntAlterNotToEscape()
        {
            var value = "abcdefghijklmnopqrstuvwxyz0123456789+-/!\"ß$%&/=?¥`'#‰ˆ¸ƒ÷‹-_.:,;@^∞<>|";
            var escaped = Escaper.EscapeValue(value);
            Assert.Equal(value, escaped);
            var unescaped = Escaper.UnescapeValue(escaped);
            Assert.Equal(value, unescaped);
        }

        [Theory]
        [InlineData("\\", "\\5c")]
        [InlineData("*", "\\2a")]
        [InlineData("(", "\\28")]
        [InlineData(")", "\\29")]
        [InlineData("\0", "\\00")]
        [InlineData("s\\tr**ange () va)(lue(\0) wi\\\\th ma*y spe*(\\)al c\0ars", 
            "s\\5ctr\\2a\\2aange \\28\\29 va\\29\\28lue\\28\\00\\29 wi\\5c\\5cth ma\\2ay spe\\2a\\28\\5c\\29al c\\00ars")]
        [InlineData("asdf)", "asdf\\29")]
        [InlineData(")fdsa", "\\29fdsa")]
        [InlineData("asdf)fdsa", "asdf\\29fdsa")]
        public void CanEscapeAndUnEscape(string value, string expected)
        {
            var escaped = Escaper.EscapeValue(value);
            Assert.Equal(expected, escaped);
            var unescaped = Escaper.UnescapeValue(escaped);
            Assert.Equal(value, unescaped);
        }

        private class Escaper : LdapFilter
        {
            internal static string EscapeValue(string value)
            {
                return Escape(value);
            }

            internal static string UnescapeValue(string value)
            {
                return Unescape(value);
            }

            public override string ToString()
            {
                return "Escaper";
            }
        }
    }
}
using Xunit;

namespace zivillian.ldap.test
{
    public class LdapAttributeDescriptionTest
    {
        [Theory]
        [InlineData("2.5.4.0")]
        [InlineData("cn;lang-de;lang-en")]
        [InlineData("owner")]
        public void CanParseAttributeDescription(string descr)
        {
            var parsed = new LdapAttributeDescription(descr);
            Assert.Equal(descr, parsed.ToString());
        }

        [Fact]
        public void CanParseOptions()
        {
            var descr = "cn;lang-de;lang-en";
            var parsed = new LdapAttributeDescription(descr);
            Assert.Equal("cn", parsed.Oid);
            Assert.Equal(2, parsed.Options.Length);
            Assert.Equal("lang-de", parsed.Options[0]);
            Assert.Equal("lang-en", parsed.Options[1]);
        }
    }
}
using Xunit;

namespace zivillian.ldap.test
{
    public class AttributeSelectionTest
    {
        [Fact]
        public void NoAttributes()
        {
            var selection = new LdapAttributeSelection("1.1");
            Assert.True(selection.NoAttributes);
            Assert.False(selection.AllUserAttributes);
            Assert.Null(selection.Selector);
            Assert.Equal("1.1", selection.ToString());
        }

        [Fact]
        public void AllUserAttributes()
        {
            var selection = new LdapAttributeSelection("*");
            Assert.False(selection.NoAttributes);
            Assert.True(selection.AllUserAttributes);
            Assert.Null(selection.Selector);
            Assert.Equal("*", selection.ToString());
        }

        [Theory]
        [InlineData("supportedControl")]
        [InlineData("configurationNamingContext")]
        public void Selection(string value)
        {
            var selection = new LdapAttributeSelection(value);
            Assert.False(selection.NoAttributes);
            Assert.False(selection.AllUserAttributes);
            Assert.NotNull(selection.Selector);
            Assert.Equal(value, selection.ToString());
        }
    }
}
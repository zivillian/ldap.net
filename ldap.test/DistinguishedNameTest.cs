using System;
using Xunit;

namespace zivillian.ldap.test
{
    public class DistinguishedNameTest
    {
        [Theory]
        [InlineData("UID=jsmith,DC=example,DC=net")]
        [InlineData("OU=Sales+CN=J.  Smith,DC=example,DC=net")]
        [InlineData("CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net")]
        [InlineData("CN=Before\\0dAfter,DC=example,DC=net", "CN=Before\rAfter,DC=example,DC=net")]
        [InlineData("1.3.6.1.4.1.1466.0=#04024869")]
        [InlineData("CN=Lu\\C4\\8Di\\C4\\87", "CN=Lučić")]
        [InlineData("CN=test=user,DC=example,DC=ne=t")]
        [InlineData("CN=test\\=user", "CN=test=user")]
        [InlineData("CN=esc\\+aped+OU=\\+plus\\+,DC=example,DC=net")]
        public void CanParseDN(string dn, string expected = null)
        {
            var parsed = new LdapDistinguishedName(dn);
            if (expected == null)
                expected = dn;
            Assert.Equal(expected, parsed.ToString());
        }

        [Fact]
        public void CanParseUnescapedEqual()
        {
            var dn = "CN=test=user,DC=example,DC=ne=t";
            var parsed = new LdapDistinguishedName(dn);
            Assert.Equal(3, parsed.RDNs.Length);
            var value = Assert.Single(parsed.RDNs[0].Values);
            Assert.Equal("CN", value.Type);
            Assert.Equal("test=user", value.Value);
            value = Assert.Single(parsed.RDNs[1].Values);
            Assert.Equal("DC", value.Type);
            Assert.Equal("example", value.Value);
            value = Assert.Single(parsed.RDNs[2].Values);
            Assert.Equal("DC", value.Type);
            Assert.Equal("ne=t", value.Value);
        }
    }
}
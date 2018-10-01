using Xunit;

namespace zivillian.ldap.test
{
    public class LdapFilterTest
    {
        [Theory]
        [InlineData("(objectclass=*)")]
        [InlineData("(cn=Babs Jensen)")]
        [InlineData("(!(cn=Tim Howes))")]
        [InlineData("(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))")]
        [InlineData("(o=univ*of*mich*)")]
        [InlineData("(seeAlso=)")]
        [InlineData("(cn:caseExactMatch:=Fred Flintstone)")]
        [InlineData("(cn:=Betty Rubble)")]
        [InlineData("(sn:dn:2.4.6.8.10:=Barney Rubble)")]
        [InlineData("(o:dn:=Ace Industry)")]
        [InlineData("(:1.2.3:=Wilma Flintstone)")]
        [InlineData("(:DN:2.4.6.8.10:=Dino)", "(:dn:2.4.6.8.10:=Dino)")]
        [InlineData(@"(o=Parens R Us \28for all your parenthetical needs\29)")]
        [InlineData(@"(cn=*\2A*)", @"(cn=*\2a*)")]
        [InlineData(@"(filename=C:\5cMyFile)")]
        [InlineData(@"(bin=\00\00\00\04)", "(bin=\\00\\00\\00\u0004)")]
        [InlineData(@"(sn=Lu\c4\8di\c4\87)", "(sn=Lučić)")]
        [InlineData(@"(1.3.6.1.4.1.1466.0=\04\02\48\69)", "(1.3.6.1.4.1.1466.0=\u0004\u0002Hi)")]
        [InlineData("(sn>=asdf)")]
        [InlineData("(sn<=asdf)")]
        [InlineData("(sn~=asdf)")]
        public void CanParseFilter(string filter, string expected = null)
        {
            var ldapFilter = LdapFilter.Parse(filter);
            var text = ldapFilter.ToString();
            Assert.Equal(expected ?? filter, text);
        }
    }
}
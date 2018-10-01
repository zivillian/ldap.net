using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace zivillian.ldap.test
{
    public class LdapClientTest
    {
        private static readonly string Hostname = "ldap.forumsys.com";

        [Fact]
        public async Task CanBind()
        {
            using (var client = new LdapClient(Hostname))
            {
                await client.SimpleBindAsync("cn=read-only-admin,dc=example,dc=com", "password",
                    CancellationToken.None);
            }
        }

        [Fact]
        public async Task CanBindAndUnbind()
        {
            using (var client = new LdapClient(Hostname))
            {
                await client.SimpleBindAsync("cn=read-only-admin,dc=example,dc=com", "password",
                    CancellationToken.None);
                await client.UnbindAsync(CancellationToken.None);
            }
        }

        [Fact]
        public async Task CanReadEntry()
        {
            using (var client = new LdapClient(Hostname))
            {
                var result = await client.SearchAsync("uid=tesla,dc=example,dc=com", SearchScope.BaseObject, null, CancellationToken.None);
                var entry = Assert.Single(result.Entries);
                Assert.Equal("uid=tesla,dc=example,dc=com", entry.ObjectName.ToString());
                Assert.Empty(result.References);
            }
        }

        [Theory]
        [InlineData("(uid=tesla)", "uid=tesla,dc=example,dc=com")]
        [InlineData("(uidNumber~=88888)", "uid=tesla,dc=example,dc=com")]
        [InlineData("(|(|(|(uid=*Boyle*)(displayName=*Boyle*))(cn=*Boyle*))(sn=*Boyle*))", "uid=boyle,dc=example,dc=com")]
        public async Task CanSearch(string filter, string dn)
        {
            using (var client = new LdapClient(Hostname))
            {
                var result = await client.SearchAsync("dc=example,dc=com", SearchScope.SingleLevel, filter,  CancellationToken.None);
                var entry = Assert.Single(result.Entries);
                Assert.Equal(dn, entry.ObjectName.ToString());
                Assert.Empty(result.References);
                result = await client.SearchAsync("dc=example,dc=com", SearchScope.BaseObject, filter, CancellationToken.None);
                Assert.Empty(result.Entries);
                Assert.Empty(result.References);
            }
        }

        [Theory]
        [InlineData("(uid=boyle)", "uid=boyle,dc=example,dc=com", "telephoneNumber", "999-867-5309")]
        [InlineData("(uid=tesla)", "uid=tesla,dc=example,dc=com", "telephoneNumber", "")]
        [InlineData("(uid=boyle)", "uid=boyle,dc=example,dc=com", "2.5.4.20", "999-867-5309", "telephoneNumber")]
        public async Task CanSearchWithAttributes(string filter, string dn, string attributeName, string attribute, string expectedAttributeName = null)
        {
            using (var client = new LdapClient(Hostname))
            {
                var result = await client.SearchAsync("dc=example,dc=com", SearchScope.SingleLevel, filter, new []{attributeName},  CancellationToken.None);
                var entry = Assert.Single(result.Entries);
                Assert.Equal(dn, entry.ObjectName.ToString());
                Assert.Empty(result.References);
                if (!String.IsNullOrEmpty(attribute))
                {
                    var attr = Assert.Single(entry.Attributes);
                    Assert.Equal(expectedAttributeName??attributeName, attr.Type.ToString());
                    var attrValue = Assert.Single(attr.Values);
                    Assert.Equal(attribute, Encoding.UTF8.GetString(attrValue.Span));
                }
                else
                {
                    Assert.Empty(entry.Attributes);
                }
            }
        }

        [Fact]
        public async Task CanCompare()
        {
            using (var client = new LdapClient(Hostname))
            {
                var result = await client.CompareAsync("ou=chemists,dc=example,dc=com", "cn", "Chemists", CancellationToken.None);
                Assert.True(result);
                result = await client.CompareAsync("ou=chemists,dc=example,dc=com", "cn", "ChemistS", CancellationToken.None);
                Assert.True(result);
                result = await client.CompareAsync("ou=chemists,dc=example,dc=com", "cn", "Foo", CancellationToken.None);
                Assert.False(result);
                var ex = await Assert.ThrowsAsync<LdapException>(() => client.CompareAsync("ou=chemists,dc=example,dc=com", "ad", "void", CancellationToken.None));
                Assert.Equal(ResultCode.UndefinedAttributeType, ex.ResultCode);
            }
        }
    }
}
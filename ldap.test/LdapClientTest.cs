using System;
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
    }
}
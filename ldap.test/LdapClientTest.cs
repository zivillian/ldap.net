using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace zivillian.ldap.test
{
    public class LdapClientTest
    {
        [Fact]
        public async Task CanBind()
        {
            using (var client = new LdapClient("ldap.forumsys.com"))
            {
                await client.SimpleBindAsync("cn=read-only-admin,dc=example,dc=com", "password",
                    CancellationToken.None);
            }
        }

        [Fact]
        public async Task CanBindAndUnbind()
        {
            using (var client = new LdapClient("ldap.forumsys.com"))
            {
                await client.SimpleBindAsync("cn=read-only-admin,dc=example,dc=com", "password",
                    CancellationToken.None);
                await client.UnbindAsync(CancellationToken.None);
            }
        }
    }
}
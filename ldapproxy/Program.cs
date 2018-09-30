using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Options;

namespace zivillian.ldap.proxy
{
    class Program
    {
        static async Task Main(string[] args)
        {
            ushort clientPort = 389;
            string serverUri = null;
            var options = new OptionSet
            {
                {"b|bind=", "bind to local port", (ushort x)=>clientPort = x},
                {"s|server=", "LDAP Server uri", x=>serverUri = x},
            };
            try
            {
                var extra = options.Parse(args);
            }
            catch (OptionException ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
            var uri = new Uri(serverUri);
            using (var proxy = new LoggingProxy(clientPort, uri.Host, (ushort) uri.Port))
            using (var cts = new CancellationTokenSource())
            {
                Console.CancelKeyPress += (s, e) =>
                {
                    cts.Cancel();
                    e.Cancel = true;
                };
                await proxy.RunAsync(cts.Token);
            }
        }
    }
}

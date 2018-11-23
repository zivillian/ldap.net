using System.Collections.Generic;
using System.IO;
using Xunit;

namespace zivillian.ldap.test
{
    public class ProtosTest
    {
        private static readonly string EncDirectory = @"..\..\..\data\enc\";
        private static readonly string AppDirectory = @"..\..\..\data\app\";

        [Fact]
        public void CanReadBEREnc()
        {
            var files = new DirectoryInfo(EncDirectory).GetFiles();
            Assert.NotEmpty(files);
            foreach (var file in files)
            {
                var data = File.ReadAllBytes(file.FullName);
                try
                {
                    var ldap = LdapReader.ReadMessage(data);
                    data = LdapReader.WriteMessage(ldap);
                    Assert.NotEmpty(data);
                }
                catch (LdapException)
                {
                }
            }
        }

        [Fact]
        public void CanReadApp()
        {
            var files = new DirectoryInfo(AppDirectory).GetFiles();
            Assert.NotEmpty(files);
            foreach (var file in files)
            {
                var data = File.ReadAllBytes(file.FullName);
                try
                {
                    var ldap = LdapReader.ReadMessage(data);
                    data = LdapReader.WriteMessage(ldap);
                    Assert.NotEmpty(data);
                }
                catch (LdapException)
                {
                }
            }
        }
    }
}
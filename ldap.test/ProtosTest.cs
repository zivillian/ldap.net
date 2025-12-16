using System.Collections.Generic;
using System.IO;
using Xunit;

namespace zivillian.ldap.test
{
    public class ProtosTest
    {
        private static readonly string EncDirectory = Path.Combine("..", "..", "..", "data", "enc");
        private static readonly string AppDirectory = Path.Combine("..", "..", "..", "data", "app");

        public static IEnumerable<object[]> GetEncFiles()
        {
            return GetFiles(EncDirectory);
        }

        public static IEnumerable<object[]> GetAppFiles()
        {
            return GetFiles(AppDirectory);
        }

        private static IEnumerable<object[]> GetFiles(string directory)
        {
            var files = new DirectoryInfo(directory).GetFiles();
            Assert.NotEmpty(files);

            foreach (var file in files)
            {
                yield return [file.Name];
            }
        }

        [Theory]
        [MemberData(nameof(GetEncFiles))]
        public void CanReadBEREnc(string filename)
        {
            var data = File.ReadAllBytes(Path.Combine(EncDirectory, filename));
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

        [Theory]
        [MemberData(nameof(GetAppFiles))]
        public void CanReadApp(string filename)
        {
            var data = File.ReadAllBytes(Path.Combine(AppDirectory, filename));
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
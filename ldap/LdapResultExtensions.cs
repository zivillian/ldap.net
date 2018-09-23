using System;
using System.Text;

namespace zivillian.ldap
{
    internal static class LdapResultExtensions
    {
        public static string[] GetReferrals(this ILdapResult source, ReadOnlyMemory<byte>[] referral)
        {
            if (referral == null || referral.Length == 0) 
                return new string[0];

            var result = new string[referral.Length];
            for (int i = 0; i < referral.Length; i++)
            {
                result[i] = referral[i].Span.LdapString();
            }
            return result;
        }

        public static ReadOnlyMemory<byte>[] GetReferrals(this ILdapResult source, string[] referral)
        {
            if (referral == null || referral.Length == 0)
                return null;

            var result = new ReadOnlyMemory<byte>[referral.Length];
            for (int i = 0; i < referral.Length; i++)
            {
                result[i] = referral[i].LdapString();
            }
            return result;
        }
    }
}
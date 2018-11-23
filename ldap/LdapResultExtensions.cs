using System;
using System.Collections.Generic;
using System.Text;

namespace zivillian.ldap
{
    internal static class LdapResultExtensions
    {
        public static string[] GetReferrals(this ILdapResult source, ReadOnlyMemory<byte>[] referral)
        {
            return GetReferrals(referral);
        }

        public static string[] GetReferrals(ReadOnlyMemory<byte>[] referral)
        {
            if (referral is null || referral.Length == 0) 
                return Array.Empty<string>();

            var result = new string[referral.Length];
            for (int i = 0; i < referral.Length; i++)
            {
                result[i] = referral[i].Span.LdapString();
            }
            return result;
        }

        public static ReadOnlyMemory<byte>[] GetReferrals(this ILdapResult source, IReadOnlyList<string> referral)
        {
            return GetReferrals(referral);
        }

        public static ReadOnlyMemory<byte>[] GetReferrals(IReadOnlyList<string> referral)
        {
            if (referral is null || referral.Count == 0)
                return null;

            var result = new ReadOnlyMemory<byte>[referral.Count];
            for (int i = 0; i < referral.Count; i++)
            {
                result[i] = referral[i].LdapString();
            }
            return result;
        }
    }
}
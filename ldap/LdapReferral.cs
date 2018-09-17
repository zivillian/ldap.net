using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public static class LdapReferral
    {
        internal static string[] Create(Asn1Referral[] referral)
        {
            if (referral == null)
                return new string[0];
            var result = new string[referral.Length];
            for (int i = 0; i < referral.Length; i++)
            {
                result[i] = Encoding.ASCII.GetString(referral[i].Uri.Span);
            }
            return result;
        }
    }
}
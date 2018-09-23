namespace zivillian.ldap
{
    public interface ILdapResult
    {
        ResultCode ResultCode { get; }

        LdapDistinguishedName MatchedDN { get; }

        string DiagnosticMessage { get; }
        
        string[] Referrals { get; }

    }
}
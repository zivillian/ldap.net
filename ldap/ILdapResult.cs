namespace zivillian.ldap
{
    public interface ILdapResult
    {
        ResultCode ResultCode { get; }

        string MatchedDN { get; }

        string DiagnosticMessage { get; }
        
        string[] Referrals { get; }

    }
}
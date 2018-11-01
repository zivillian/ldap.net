using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace zivillian.ldap
{
    public interface ILdapResult
    {
        ResultCode ResultCode { get; }

        LdapDistinguishedName MatchedDN { get; }

        string DiagnosticMessage { get; }
        
        IReadOnlyList<string> Referrals { get; }

    }
}
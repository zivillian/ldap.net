using System;

namespace zivillian.ldap
{
    public class LdapServerException:Exception
    {
        public LdapServerException(ILdapResult result)
        :base(result.DiagnosticMessage)
        {
            ResultCode = result.ResultCode;
        }

        public ResultCode ResultCode { get; }
    }
}
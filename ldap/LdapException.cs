using System;

namespace zivillian.ldap
{
    public class LdapException:Exception
    {
        public LdapException(ILdapResult result)
            : this(result.ResultCode, result.DiagnosticMessage)
        {
        }

        public LdapException(ResultCode resultCode)
            : this(resultCode, resultCode.ToString())
        {
        }

        public LdapException(ResultCode resultCode, string message)
            : base(message)
        {
            ResultCode = resultCode;
        }

        public LdapException(ResultCode resultCode, string message, Exception innerException)
            : base(message, innerException)
        {
            ResultCode = resultCode;
        }

        public ResultCode ResultCode { get; }
    }

    public class InvalidDnSyntaxException : LdapException
    {
        public InvalidDnSyntaxException()
            : base(ResultCode.InvalidDnSyntax)
        {
        }
        public InvalidDnSyntaxException(string message)
            : base(ResultCode.InvalidDnSyntax, message)
        {
        }
    }

    public class LdapProtocolException : LdapException
    {
        public LdapProtocolException()
        :base (ResultCode.ProtocolError)
        {
        }

        public LdapProtocolException(string message)
        :base (ResultCode.ProtocolError, message)
        {
        }

        public LdapProtocolException(string message, Exception innerException)
            : base(ResultCode.ProtocolError, message, innerException)
        {
        }
    }

    public class LdapFilterParseException : LdapException
    {
        public LdapFilterParseException(string message)
            : base(ResultCode.ProtocolError, message)
        {
        }
    }
}
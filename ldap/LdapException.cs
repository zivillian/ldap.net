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
            : this(message)
        {
            ResultCode = resultCode;
        }

        public LdapException(ResultCode resultCode, string message, Exception innerException)
            : this(message, innerException)
        {
            ResultCode = resultCode;
        }

        public LdapException()
        {
        }

        public LdapException(string message)
            : base(message)
        {
        }

        public LdapException(string message, Exception innerException)
            : base(message, innerException)
        {
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

        public InvalidDnSyntaxException(string message, Exception innerException)
            : base(message, innerException)
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
        public LdapFilterParseException()
        {
        }

        public LdapFilterParseException(string message)
            : base(ResultCode.ProtocolError, message)
        {
        }

        public LdapFilterParseException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
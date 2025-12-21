using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace zivillian.ldap.Asn1
{
    internal sealed partial class Asn1SearchResultEntry
    {
        internal void DecodeAdditional()
        {
            foreach(var attribute in Attributes)
            {
                attribute.DecodeAdditional();
            }
        }
    }

    internal sealed partial class Asn1PartialAttribute
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1LDAPResult
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1ModifyRequest
    {
        internal void DecodeAdditional()
        {
            foreach (var change in Changes)
            {
                change.DecodeAdditional();
            }
        }
    }

    internal sealed partial class Asn1Change
    {
        internal void DecodeAdditional()
        {
            Modification.DecodeAdditional();
        }
    }

    internal sealed partial class Asn1AddRequest
    {
        internal void DecodeAdditional()
        {
            foreach (var attribute in Attributes)
            {
                attribute.DecodeAdditional();
            }
        }
    }

    internal sealed partial class Asn1BindRequest
    {
        internal void DecodeAdditional()
        {
            Authentication.DecodeAdditional();
        }
    }

    internal sealed partial class Asn1AuthenticationChoice
    {
        internal void DecodeAdditional()
        {
            Sasl?.DecodeAdditional();
        }
    }

    internal sealed partial class Asn1SaslCredentials
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1CompareRequest
    {
        internal void DecodeAdditional()
        {
            Assertion.DecodeAdditional();
        }
    }

    internal sealed partial class Asn1AttributeValueAssertion
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1LdapMessage
    {
        internal void DecodeAdditional()
        {
            ProtocolOp.DecodeAdditional();
        }
    }

    internal sealed partial class Asn1BindResponse
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1SearchRequest
    {
        internal void DecodeAdditional()
        {
            Filter.DecodeAdditional();
            DecodeSizeLimit();
        }
    }

    internal sealed partial class Asn1Filter
    {
        internal void DecodeAdditional()
        {
            if (And is not null)
            {
                foreach (var and in And)
                {
                    and.DecodeAdditional();
                }
            }
            if (Or is not null)
            {
                foreach (var or in Or)
                {
                    or.DecodeAdditional();
                }
            }
            Not?.DecodeAdditional();
            EqualityMatch?.DecodeAdditional();
            Substrings?.DecodeAdditional();
            GreaterOrEqual?.DecodeAdditional();
            LessOrEqual?.DecodeAdditional();
            ApproxMatch?.DecodeAdditional();
            ExtensibleMatch?.DecodeAdditional();
        }
    }

    internal sealed partial class Asn1SubstringFilter
    {
        internal void DecodeAdditional()
        {
            foreach (var substring in Substrings)
            {
                substring.DecodeAdditional();
            }
        }
    }

    internal sealed partial class Asn1Substring
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1MatchingRuleAssertion
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1ModifyDNRequest
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1ExtendedRequest
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1ExtendedResponse
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1IntermediateResponse
    {
        internal void DecodeAdditional()
        {
        }
    }

    internal sealed partial class Asn1ProtocolOp
    {
        internal void DecodeAdditional()
        {
            BindRequest?.DecodeAdditional();
            BindResponse?.DecodeAdditional();
            SearchRequest?.DecodeAdditional();
            SearchResEntry?.DecodeAdditional();
            SearchResultDone?.DecodeAdditional();
            ModifyRequest?.DecodeAdditional();
            ModifyResponse?.DecodeAdditional();
            AddRequest?.DecodeAdditional();
            AddResponse?.DecodeAdditional();
            DelResponse?.DecodeAdditional();
            ModifyDNRequest?.DecodeAdditional();
            ModifyDNResponse?.DecodeAdditional();
            CompareRequest?.DecodeAdditional();
            CompareResponse?.DecodeAdditional();
            ExtendedRequest?.DecodeAdditional();
            ExtendedResponse?.DecodeAdditional();
            IntermediateResponse?.DecodeAdditional();
        }
    }
}

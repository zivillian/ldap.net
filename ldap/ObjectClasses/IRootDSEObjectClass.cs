using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    public interface IRootDSEObjectClass
    {
        AltServerAttribute AltServer { get; set; }

        NamingContextsAttribute NamingContexts { get; set; }

        SupportedControlAttribute SupportedControl { get; set; }

        SupportedExtensionAttribute SupportedExtension { get; set; }

        SupportedFeaturesAttribute SupportedFeatures { get; set; }

        SupportedLDAPVersionAttribute SupportedLDAPVersion { get; set; }
        
        SupportedSASLMechanismsAttribute SupportedSASLMechanisms { get; set; }
    }
}
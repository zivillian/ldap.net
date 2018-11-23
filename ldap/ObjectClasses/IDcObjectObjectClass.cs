using zivillian.ldap.Attributes;

namespace zivillian.ldap.ObjectClasses
{
    /// <summary>
    /// dcObject
    /// </summary>
    public interface IDcObjectObjectClass
    {
        DcAttribute Dc { get; }
    }
}
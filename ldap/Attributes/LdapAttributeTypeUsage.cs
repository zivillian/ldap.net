namespace zivillian.ldap.Attributes
{
    public enum LdapAttributeTypeUsage
    {
        /// <summary>
        /// user
        /// </summary>
        UserApplication,
        /// <summary>
        /// directory operational
        /// </summary>
        DirectoryOperation,
        /// <summary>
        /// DSA-shared operational
        /// </summary>
        DistributedOperation,
        /// <summary>
        /// DSA-specific operational
        /// </summary>
        DSAOperation
    }
}
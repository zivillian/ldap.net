namespace zivillian.ldap.Attributes
{
    public class ModifyTimestampAttribute : GeneralizedTimeAttribute
    {
        private const string _name = "modifyTimestamp";

        public ModifyTimestampAttribute()
            :base(_name)
        {
        }

        public override string Oid => "2.5.18.2";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DirectoryOperation;
    }
}
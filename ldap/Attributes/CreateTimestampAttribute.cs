namespace zivillian.ldap.Attributes
{
    public class CreateTimestampAttribute : GeneralizedTimeAttribute
    {
        private const string _name = "createTimestamp";

        public CreateTimestampAttribute()
            :base(_name)
        {
        }

        public override string Oid => "2.5.18.1";

        public override string Name => _name;

        public override LdapAttributeTypeUsage Usage => LdapAttributeTypeUsage.DirectoryOperation;
    }
}
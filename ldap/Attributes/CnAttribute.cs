namespace zivillian.ldap.Attributes
{
    public class CnAttribute : NameAttribute
    {
        private static readonly string _name = "cn";

        public CnAttribute()
            :base(_name)
        {
        }

        public override string Oid => "2.5.4.3";

        public override string Name => _name;
    }
}
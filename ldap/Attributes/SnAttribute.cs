namespace zivillian.ldap.Attributes
{
    public class SnAttribute : NameAttribute
    {
        private static readonly string _name = "sn";

        public SnAttribute()
            :base(_name)
        {
        }

        public override string Oid => "2.5.4.4";

        public override string Name => _name;
    }
}
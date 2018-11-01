namespace zivillian.ldap.Attributes
{
    public class OuAttribute : NameAttribute
    {
        private const string _name = "ou";

        public OuAttribute()
            :base(_name)
        {
        }
        public override string Oid => "2.5.4.11";

        public override string Name => _name;
    }
}
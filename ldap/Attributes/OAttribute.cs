namespace zivillian.ldap.Attributes
{
    public class OAttribute : NameAttribute
    {
        private const string _name = "o";

        public OAttribute()
            :base(_name)
        {
        }
        public override string Oid => "2.5.4.10";

        public override string Name => _name;
    }
}
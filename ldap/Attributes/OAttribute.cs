namespace zivillian.ldap.Attributes
{
    public class OAttribute : NameAttribute
    {
        private static readonly string _name = "o";
        
        public OAttribute()
            :base(_name)
        {
        }
        public override string Oid => "2.5.4.10";

        public override string Name => _name;
    }
}
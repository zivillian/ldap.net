namespace zivillian.ldap.Attributes
{
    public class LocalityAttribute : NameAttribute
    {
        private static readonly string _name = "l";
        
        public LocalityAttribute()
        :base(_name)
        {
        }

        public override string Oid => "2.5.4.7";

        public override string Name => _name;

    }
}
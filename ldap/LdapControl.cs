using System;
using System.Text;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapControl
    {
        internal LdapControl(Asn1Control control)
        {
            Oid = Encoding.UTF8.GetString(control.Type.Span);
            Criticality = control.Criticality;
            Value = control.Value;
        }

        public ReadOnlyMemory<byte>? Value { get; set; }

        public bool Criticality { get; }

        public string Oid { get; }

        internal static LdapControl[] Create(Asn1Control[] controls)
        {
            if (controls == null)
                return new LdapControl[0];
            var result = new LdapControl[controls.Length];
            for (int i = 0; i < controls.Length; i++)
            {
                result[i] = new LdapControl(controls[i]);
            }
            return result;
        }
    }
}
using System;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapControl
    {
        internal LdapControl(Asn1Control control)
        {
            Oid = control.Type.Span.NumericOid();
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

        internal static Asn1Control[] Create(LdapControl[] controls)
        {
            if (controls == null)
                return null;
            if (controls.Length == 0)
                return null;
            var result = new Asn1Control[controls.Length];
            for (int i = 0; i < controls.Length; i++)
            {
                var control = controls[i];
                result[i] = new Asn1Control
                {
                    Type = control.Oid.NumericOid(),
                    Criticality = control.Criticality,
                    Value = control.Value
                };
            }
            return result;
        }
    }
}
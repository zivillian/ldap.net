using System;
using System.Collections.Generic;
using zivillian.ldap.Asn1;

namespace zivillian.ldap
{
    public class LdapControl
    {
        internal LdapControl(Asn1Control control)
        {
            Oid = control.Type.Span.NumericOid();
            Criticality = control.Criticality.GetValueOrDefault();
            Value = control.Value;
        }

        public ReadOnlyMemory<byte>? Value { get; set; }

        public bool Criticality { get; }

        public string Oid { get; }

        internal static LdapControl[] Create(Asn1Control[] controls)
        {
            if (controls is null)
                return Array.Empty<LdapControl>();
            var result = new LdapControl[controls.Length];
            for (int i = 0; i < controls.Length; i++)
            {
                result[i] = new LdapControl(controls[i]);
            }
            return result;
        }

        internal static Asn1Control[] Create(IReadOnlyList<LdapControl> controls)
        {
            if (controls is null)
                return null;
            if (controls.Count == 0)
                return null;
            var result = new Asn1Control[controls.Count];
            for (int i = 0; i < controls.Count; i++)
            {
                var control = controls[i];
                result[i] = new Asn1Control
                {
                    Type = control.Oid.NumericOid(),
                    Value = control.Value
                };
                if (control.Criticality)
                    result[i].Criticality = true;
            }
            return result;
        }
    }
}
using System.Diagnostics.CodeAnalysis;

namespace zivillian.ldap
{
    [SuppressMessage("Naming", "CA1717:Only FlagsAttribute enums should have plural names", Justification = "rfc4511 section 4.5.1")]
    public enum DerefAliases
    {
        /*
         * ENUMERATED {
         *           neverDerefAliases       (0),
         *           derefInSearching        (1),
         *           derefFindingBaseObj     (2),
         *           derefAlways             (3) },
         */
        NeverDerefAliases = 0,
        DerefInSearching = 1,
        DerefFindingBaseObj = 2,
        DerefAlways = 3,
    }
}
namespace zivillian.ldap
{
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
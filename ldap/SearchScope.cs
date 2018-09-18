namespace zivillian.ldap
{
    public enum SearchScope
    {
        /*
         * ENUMERATED {
         *           baseObject              (0),
         *           singleLevel             (1),
         *           wholeSubtree            (2),
         *           ...  },
         */
        BaseObject = 0,
        SingleLevel = 1,
        WholeSubtree = 2,
    }
}
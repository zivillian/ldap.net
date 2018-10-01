using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks.Dataflow;

namespace zivillian.ldap
{
    public class LdapSearchResult
    {
        private readonly List<LdapSearchResultEntry> _entries;
        private readonly List<LdapSearchResultReference> _references;

        internal LdapSearchResult()
        {
            _entries = new List<LdapSearchResultEntry>();
            _references = new List<LdapSearchResultReference>();
        }

        internal bool Add(LdapRequestMessage message)
        {
            if (message is LdapSearchResultEntry entry)
            {
                _entries.Add(entry);
                return true;
            }
            else if (message is LdapSearchResultReference reference)
            {
                _references.Add(reference);
                return true;
            }
            else if (message is LdapSearchResultDone)
            {
                return false;
            }
            else
            {
                throw new LdapProtocolException($"unexpected response type '{message.GetType().FullName}'");
            }
        }

        public IEnumerable<LdapSearchResultEntry> Entries
        {
            get { return _entries; }
        }

        public IEnumerable<LdapSearchResultReference> References
        {
            get { return _references; }
        }
    }
}
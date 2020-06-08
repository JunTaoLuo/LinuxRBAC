using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Negotiate
{
    public static class LinuxAdapter
    {
        // example: machineAccount = "user@DOMAIN.com" machinePassword = "***"
        public static Task OnAuthenticated(AuthenticatedContext context, string machineAccount, string machinePassword, bool resolveNestedGroups = true)
        {
            var domain = machineAccount.Substring(machineAccount.IndexOf('@') + 1);
            var distinguishedName = domain.Split('.').Select(name => $"dc={name}").Aggregate((a, b) => $"{a},{b}");
            var user = context.Principal.Identity.Name;
            var userAccountName = user.Substring(0, user.IndexOf('@'));

            LdapDirectoryIdentifier di = new LdapDirectoryIdentifier(domain, true, false);
            NetworkCredential credential = new NetworkCredential(machineAccount, machinePassword);
            using LdapConnection connection = new LdapConnection(di, credential);
            connection.SessionOptions.ProtocolVersion = 3; //Setting LDAP Protocol to latest version
            connection.Bind(); // This line actually makes the connection.
            connection.Timeout = TimeSpan.FromMinutes(3);
            string filter = $"(&(objectClass=user)(sAMAccountName={userAccountName}))"; // This is using ldap search query language, it is looking on the server for someUser
            SearchRequest searchRequest = new SearchRequest(distinguishedName, filter, SearchScope.Subtree, null);
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count > 0)
            {
                var userFound = searchResponse.Entries[0]; //Get the object that was found on ldap
                string name = userFound.DistinguishedName;
                var memberof = userFound.Attributes["memberof"]; // You can access ldap Attributes with Attributes property

                foreach (var group in memberof)
                {
                    var groupDN = $"{Encoding.UTF8.GetString((byte[])group)}";
                    var groupCN = groupDN.Split(',')[0].Substring("CN=".Length);

                    if (resolveNestedGroups)
                    {
                        GetNestedGroups(connection, context.Principal.Identity, distinguishedName, groupCN);
                    }
                    else
                    {
                        context.Principal.Identity.AddRole(groupCN);
                    }
                }
            }

            return Task.CompletedTask;
        }

        private static void GetNestedGroups(LdapConnection connection, IIdentity principal, string searchDN, string groupCN)
        {
            string filter = $"(&(objectClass=group)(sAMAccountName={groupCN}))"; // This is using ldap search query language, it is looking on the server for someUser
            SearchRequest searchRequest = new SearchRequest(searchDN, filter, System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count > 0)
            {
                var group = searchResponse.Entries[0]; //Get the object that was found on ldap
                string name = group.DistinguishedName;
                principal.AddRole(name);

                var memberof = group.Attributes["memberof"]; // You can access ldap Attributes with Attributes property
                if (memberof != null)
                {
                    foreach (var member in memberof)
                    {
                        var groupDN = $"{Encoding.UTF8.GetString((byte[])member)}";
                        var nestedGroupCN = groupDN.Split(',')[0].Substring("CN=".Length);
                        GetNestedGroups(connection, principal, searchDN, nestedGroupCN);
                    }
                }
            }
        }

        private static void AddRole(this IIdentity identity, string role)
        {
            var claimsIdentity = identity as ClaimsIdentity;
            claimsIdentity.AddClaim(new Claim(claimsIdentity.RoleClaimType, role));
        }
    }
}

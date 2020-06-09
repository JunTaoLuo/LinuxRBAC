using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Negotiate
{
    public static class LinuxAdapter
    {
        // example: machineAccount = "user@DOMAIN.com" machinePassword = "***"
        public static Task OnAuthenticated(AuthenticatedContext context, string machineAccount, string machinePassword, bool resolveNestedGroups = true)
        {
            var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("LinuxAdapter");

            var domain = machineAccount.Substring(machineAccount.IndexOf('@') + 1);
            var distinguishedName = domain.Split('.').Select(name => $"dc={name}").Aggregate((a, b) => $"{a},{b}");
            var user = context.Principal.Identity.Name;
            var userAccountName = user.Substring(0, user.IndexOf('@'));

            LdapDirectoryIdentifier di = new LdapDirectoryIdentifier(server: domain, fullyQualifiedDnsHostName: true, connectionless: false);
            NetworkCredential credential = new NetworkCredential(machineAccount, machinePassword);
            using LdapConnection connection = new LdapConnection(di, credential);
            connection.SessionOptions.ProtocolVersion = 3; //Setting LDAP Protocol to latest version
            connection.Bind(); // This line actually makes the connection.
            connection.Timeout = TimeSpan.FromMinutes(1);
            string filter = $"(&(objectClass=user)(sAMAccountName={userAccountName}))"; // This is using ldap search query language, it is looking on the server for someUser
            SearchRequest searchRequest = new SearchRequest(distinguishedName, filter, SearchScope.Subtree, null);
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count > 0)
            {
                if (searchResponse.Entries.Count > 1)
                {
                    logger.LogInformation($"More than one response received for query: {filter} with distinguished name: {distinguishedName}");
                }

                var userFound = searchResponse.Entries[0]; //Get the object that was found on ldap
                string name = userFound.DistinguishedName;
                var memberof = userFound.Attributes["memberof"]; // You can access ldap Attributes with Attributes property

                var claimsIdentity = context.Principal.Identity as ClaimsIdentity;

                foreach (var group in memberof)
                {
                    // Example distinguished name: CN=TestGroup,DC=KERB,DC=local
                    var groupDN = $"{Encoding.UTF8.GetString((byte[])group)}";
                    var groupCN = groupDN.Split(',')[0].Substring("CN=".Length);

                    if (resolveNestedGroups)
                    {
                        GetNestedGroups(connection, claimsIdentity, distinguishedName, groupCN, logger);
                    }
                    else
                    {
                        AddRole(claimsIdentity, groupCN);
                    }
                }
            }

            return Task.CompletedTask;
        }

        private static void GetNestedGroups(LdapConnection connection, ClaimsIdentity principal, string searchDN, string groupCN, ILogger logger)
        {
            string filter = $"(&(objectClass=group)(sAMAccountName={groupCN}))"; // This is using ldap search query language, it is looking on the server for someUser
            SearchRequest searchRequest = new SearchRequest(searchDN, filter, System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count > 0)
            {
                if (searchResponse.Entries.Count > 1)
                {
                    logger.LogInformation($"More than one response received for query: {filter} with distinguished name: {searchDN}");
                }

                var group = searchResponse.Entries[0]; //Get the object that was found on ldap
                string name = group.DistinguishedName;
                AddRole(principal, name);

                var memberof = group.Attributes["memberof"]; // You can access ldap Attributes with Attributes property
                if (memberof != null)
                {
                    foreach (var member in memberof)
                    {
                        var groupDN = $"{Encoding.UTF8.GetString((byte[])member)}";
                        var nestedGroupCN = groupDN.Split(',')[0].Substring("CN=".Length);
                        GetNestedGroups(connection, principal, searchDN, nestedGroupCN, logger);
                    }
                }
            }
        }

        private static void AddRole(ClaimsIdentity identity, string role)
        {
            identity.AddClaim(new Claim(identity.RoleClaimType, role));
        }
    }
}

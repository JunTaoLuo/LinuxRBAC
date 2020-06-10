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
    public class LinuxAdapter
    {
        private readonly string _distinguishedName;
        private readonly LdapConnection _connection;

        public LinuxAdapter(string machineAccount, string machinePassword)
        {
            if (string.IsNullOrEmpty(machineAccount))
            {
                throw new ArgumentNullException(nameof(machineAccount));
            }
            if (string.IsNullOrEmpty(machinePassword))
            {
                throw new ArgumentNullException(nameof(machinePassword));
            }

            var domain = machineAccount.Substring(machineAccount.IndexOf('@') + 1);
            _distinguishedName = domain.Split('.').Select(name => $"dc={name}").Aggregate((a, b) => $"{a},{b}");

            LdapDirectoryIdentifier di = new LdapDirectoryIdentifier(server: domain, fullyQualifiedDnsHostName: true, connectionless: false);
            NetworkCredential credential = new NetworkCredential(machineAccount, machinePassword);
            _connection = new LdapConnection(di, credential);
            _connection.SessionOptions.ProtocolVersion = 3; //Setting LDAP Protocol to latest version
            _connection.Bind(); // This line actually makes the connection.
            _connection.Timeout = TimeSpan.FromMinutes(1);
        }

        // example: machineAccount = "user@DOMAIN.com" machinePassword = "***"
        public Task OnAuthenticated(AuthenticatedContext context, bool resolveNestedGroups = true)
        {
            var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("LinuxAdapter");

            var user = context.Principal.Identity.Name;
            var userAccountName = user.Substring(0, user.IndexOf('@'));

            string filter = $"(&(objectClass=user)(sAMAccountName={userAccountName}))"; // This is using ldap search query language, it is looking on the server for someUser
            SearchRequest searchRequest = new SearchRequest(_distinguishedName, filter, SearchScope.Subtree, null);
            SearchResponse searchResponse = (SearchResponse)_connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count > 0)
            {
                if (searchResponse.Entries.Count > 1)
                {
                    logger.LogWarning($"More than one response received for query: {filter} with distinguished name: {_distinguishedName}");
                }

                var userFound = searchResponse.Entries[0]; //Get the object that was found on ldap
                var memberof = userFound.Attributes["memberof"]; // You can access ldap Attributes with Attributes property

                var claimsIdentity = context.Principal.Identity as ClaimsIdentity;

                foreach (var group in memberof)
                {
                    // Example distinguished name: CN=TestGroup,DC=KERB,DC=local
                    var groupDN = $"{Encoding.UTF8.GetString((byte[])group)}";
                    var groupCN = groupDN.Split(',')[0].Substring("CN=".Length);

                    if (resolveNestedGroups)
                    {
                        GetNestedGroups(claimsIdentity, groupCN, logger);
                    }
                    else
                    {
                        AddRole(claimsIdentity, groupCN);
                    }
                }
            }

            return Task.CompletedTask;
        }

        private void GetNestedGroups(ClaimsIdentity principal, string groupCN, ILogger logger)
        {
            string filter = $"(&(objectClass=group)(sAMAccountName={groupCN}))"; // This is using ldap search query language, it is looking on the server for someUser
            SearchRequest searchRequest = new SearchRequest(_distinguishedName, filter, System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            SearchResponse searchResponse = (SearchResponse)_connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count > 0)
            {
                if (searchResponse.Entries.Count > 1)
                {
                    logger.LogWarning($"More than one response received for query: {filter} with distinguished name: {_distinguishedName}");
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
                        GetNestedGroups(principal, nestedGroupCN, logger);
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

# Instructions for testing RBAC support for Linux in .NET 5 preview 6

1. Install .NET 5 preview 6 SDK
   1. Instructions at https://dotnet.microsoft.com/download/dotnet/5.0.
2. Modify your project
   1. Update the TFM of your project to `net5.0`
   2. Add the following packages to your project
```xml
<PackageReference Include="System.DirectoryServices.Protocols" Version="5.0.0-preview.6.20305.6" />
<PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="5.0.0-preview.6.20312.15" />
```
   3. Add the file [LinuxAdapter.cs](https://github.com/JunTaoLuo/LinuxRBAC/blob/master/LinuxAdapter.cs) to your project
   4. Modify the `ConfigureServices` method to the following:
```C#
var adapter = new LinuxAdapter("user@DOMAIN.net", "<Password>");
services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate(options => options.Events = new NegotiateEvents()
    {
        OnAuthenticated = context => adapter.OnAuthenticated(context)
    });
```
   5. Run the project and verify roles are populated via `User.IsInRole("<Role>")`.

Note: the API shown here is not the final design. We plan to make this a built-in feature for the Negotiate middleware with options for configuration via `NegotiateOptions`.

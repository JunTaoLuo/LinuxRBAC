# Instructions for testing RBAC support for Linux in .NET 5 preview 6

1. Install .NET 5 preview 6 SDK
   1. Download the sdk tar.gz at https://dotnetcli.azureedge.net/dotnet/Sdk/5.0.100-preview.6.20306.2/dotnet-sdk-5.0.100-preview.6.20306.2-linux-x64.tar.gz and extract to a local directory. Add this directory to your PATH.
   2. Add dotnet5 feed to your NuGet.config. You may need to add a NuGet.config file to your project directory if it doesn't exist. For example:
```xml
<configuration>
  <packageSources>
    <add key="dotnet5" value="https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet5/nuget/v3/index.json" />
  </packageSources>
</configuration>
```
2. Modify your project
   1. Update the TFM of your project to `net5.0`
   2. Add the following packages to your project
```xml
<PackageReference Include="System.DirectoryServices.Protocols" Version="5.0.0-preview.6.20305.6" />
<PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="5.0.0-preview.6.20305.3" />
```
   3. Add the file [LinuxAdapter.cs](https://github.com/JunTaoLuo/LinuxRBAC/blob/master/LinuxAdapter.cs) to your project
   4. Modify the `ConfigureServices` method to the following:
```C#
services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate(options => options.Events = new NegotiateEvents()
    {
        OnAuthenticated = context => LinuxAdapter.OnAuthenticated(context, "user@DOMAIN.net", "<Password>")
    });
```
   5. Run the project and verify roles are populated via `User.IsInRole("<Role>")`.

Note: the API shown here is not the final design. We plan to make this a built-in feature for the Negotiate middleware with options for configuration via `NegotiateOptions`.

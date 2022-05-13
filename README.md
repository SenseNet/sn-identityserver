# sensenet IdentityServer
Library and service for an [IdentityServer4](https://github.com/IdentityServer/IdentityServer4) implementation that works with a [sensenet](https://github.com/SenseNet/sensenet) repository and uses OAuth 2.0 and OpenID Connect.

The purpose of this project is to provide a default basic **authentication service** for a standalone sensenet repository. This service is required to log in to sensenet.

> The auth service only provides authentication tokens and does not have a user store. Users are maintained in the sensenet repository itself.

## Authentication flow
You will have the following services:
- the authentication service (the `SenseNet.IdentityServer4.Web` Asp.Net Core MVC project that can be found here, under the `src` directory)
- a [sensenet](https://github.com/SenseNet/sensenet) repository service
- a client application: either your custom SPA application or our global [admin UI](https://admin.sensenet.com) (which you may also install locally from [this repository](https://github.com/SenseNet/sn-client))

When the application requires you to log in, it redirects you to the authentication service which this project is about. The auth service displays a login page and asks for your user credentials. It **validates your credentials with the sensenet repository service** in the background. If they are correct, your application receives an auth token that must be sent with all subsequent requests to the repository service.

> For more details please visit the [authentication basics](https://docs.sensenet.com/concepts/basics/06-authentication) article.

## Usage
You will use the `SenseNet.IdentityServer4.Web` Asp.Net Core web project that can be found here, under the `src` directory. You can start it right away using any of the well-known methods (command line `dotnet run` or Visual Studio), without any modification. It will start on the https://localhost:44311 url by default. You can also deploy it to your environment either on a physical server or a container.

> Please note that the default configuration requires you to have a repository service on https://localhost:44362. If you have sensenet on a different url, please see the repository url configuration below.

If you deploy this authentication service to a different url, you will need to configure that url on the repository side too (see below), so that the repository knows where to validate access tokens.

### Configuration
Either modify one of the `appsettings.json` files (default, Develop or Production), or specify the same configuration values in user secrets or environment variables.

#### Clients
A client is basically a type of application you want to use this auth service. By default you have the following configured clients:
- **client**: designed to work with [.Net tools](https://docs.sensenet.com/tutorials/authentication/how-to-authenticate-dotnet). Fixed clientid/secret representing a single user, no individual user login is possible.
- **spa**: dedicated to single page client applications (React/Vue/Angular etc.)
- **adminui**: dedicated to our admin user interface.
- **mvc**: dedicated to Asp.Net MVC server applications

You may change any of them, but make sure you configure the same clients (and if necessary, secrets) in the **sensenet repository service**. Otherwise you will receive an `unknown client` error when trying to log in.

> For more on configuring clients, please visit the [IdentityServer4](https://identityserver4.readthedocs.io/) documentation.

##### Allowed repositories
Clients configured to work in a web environment (e.g. `spa`, `adminui`, see above) need to know the urls of the **allowed repositories**. This is required so that unknown repositories cannot use your identity server to log in. If you want to deploy sensenet into a production environment with custom urls, you have to provide the list of allowed urls in the `RepositoryHosts` array in the configuration for **every web client**.

```json
{
  "sensenet": {
    "Clients": {
      "spa": {
        "RepositoryHosts": [ "https://example.com" ]
      }
    }
  }
}
```

#### sensenet repository configuration
These values are configured in the **sensenet repository service**, not here in the auth server! 

If you want to deploy the auth service to a different url other than the default, please provide it here as the authority:

```json
"sensenet": {
 "authentication": {
   "authority": "https://identity.example.com",
   "AddJwtCookie": true
 }
}
```

#### Logging
The auth service web application uses [Serilog](https://serilog.net) and [Graylog](https://www.graylog.org) and writes messages to the console and to log files in the `App_Data/Logs` folder.
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Logging;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.IdentityServer4.Configuration;
using SenseNet.IdentityServer4.Web.Captcha;

namespace SenseNet.IdentityServer4.Web
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();

            // configures IIS out-of-proc settings (see https://github.com/aspnet/AspNetCore/issues/14882)
            services.Configure<IISOptions>(iis =>
            {
                iis.AuthenticationDisplayName = "Windows";
                iis.AutomaticAuthentication = false;
            });

            // configures IIS in-proc settings
            services.Configure<IISServerOptions>(iis =>
            {
                iis.AuthenticationDisplayName = "Windows";
                iis.AutomaticAuthentication = false;
            });

            var builder = services.AddIdentityServer(options =>
                {
                    options.Events.RaiseErrorEvents = true;
                    options.Events.RaiseInformationEvents = true;
                    options.Events.RaiseFailureEvents = true;
                    options.Events.RaiseSuccessEvents = true;
                    options.IssuerUri = "http://SnIdentityServer";
                })
                .AddSnIdentityServerServices();

            // in-memory, code config
            builder.AddInMemoryIdentityResources(Config.Ids);
            builder.AddInMemoryApiResources(Config.GetApis());
            //builder.AddInMemoryClients(Config.Clients);

            // register SnaaSClientStore or SnClientStore (SnaaS or standalone behavior)
            builder.AddClientStore<SnClientStore>();
            
            // not recommended for production - you need to store your key material somewhere secure
            if (Environment.IsDevelopment())
            {
                IdentityModelEventSource.ShowPII = true;                
            }

            builder.AddDeveloperSigningCredential();

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    Configuration.Bind("sensenet:Authentication:ExternalProviders:Google", options);

                    options.Events = new OAuthEvents
                    {
                        OnCreatingTicket = context => AddImageClaimAsync(context, "picture")
                    };

                    // register your IdentityServer with Google at https://console.developers.google.com
                    // enable the Google+ API
                    // set the redirect URI to http://localhost:5000/signin-google
                })
                .AddGitHub(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    Configuration.Bind("sensenet:Authentication:ExternalProviders:GitHub", options);

                    options.Scope.Add("user:email");
                    options.Scope.Add("read:user");

                    options.Events = new OAuthEvents
                    {
                        OnCreatingTicket = context => AddImageClaimAsync(context, "avatar_url")
                    };
                });

            services.AddTransient<IRedirectUriValidator, DefaultRedirectUriValidator>();

            //UNDONE: inject allowed origins dynamically (do not allow everything)
            services.AddCors(c =>
            {
                c.AddPolicy("AllowAllOrigins", options =>
                {
                    options.AllowAnyOrigin();
                    options.AllowAnyHeader();
                    options.AllowAnyMethod();
                });
            });

            // [sensenet]: default sn-related services
            services.AddSnIdentityServerServices();

            // [sensenet]: configure mailing list settings
            services.Configure<SnMailChimpOptions>(Configuration.GetSection("sensenet:MailChimp"));

            // [sensenet]: configure email settings
            services.Configure<EmailSettings>(Configuration.GetSection("sensenet:Email"));
            
            // [sensenet]: login page
            services.Configure<LoginPageOptions>(Configuration.GetSection("sensenet:LoginPage"));

            // [sensenet]: notification options with backward compatibility
            services.Configure<NotificationOptions>(Configuration.GetSection("sensenet:SNaaS:Notification"));
            services.Configure<NotificationOptions>(Configuration.GetSection("sensenet:Notification"));
            
            // [sensenet]: captcha
            services.Configure<RecaptchaOptions>(Configuration.GetSection("sensenet:Captcha"));
            services.AddSingleton<IRecaptchaService, RecaptchaService>();
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseRouting();

            //UNDONE: inject allowed origins dynamically (do not allow everything)
            app.UseCors("AllowAllOrigins");

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedProto
            });
            
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }

        private static Task AddImageClaimAsync(OAuthCreatingTicketContext context, string propertyName)
        {
            // set the user image value for later use
            var picture = context.User.GetProperty(propertyName).GetString();
            context.Identity.AddClaim(new Claim("image", picture));

            return Task.FromResult(0);
        }
    }
}
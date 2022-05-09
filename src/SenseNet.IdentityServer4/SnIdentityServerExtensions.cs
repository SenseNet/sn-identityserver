using Microsoft.Extensions.DependencyInjection;
using SenseNet.IdentityServer4;

// ReSharper disable once CheckNamespace
namespace SenseNet.Extensions.DependencyInjection
{
    public static class SnIdentityServerExtensions
    {
        public static IServiceCollection AddSnIdentityServerServices(this IServiceCollection services)
        {
            return services
                    .AddTransient<IMailingListManager, MailingListManager>()
                    .AddSingleton<IEmailSender, EmailSender>()
                    .AddSingleton<ITemplateManager, AssemblyTemplateManager>()
                    .AddSenseNetClientTokenStore()
                    .AddSingleton<SnClientConnectorFactory>()
                    .AddSingleton<IRegistrationManager, DefaultRegistrationManager>()
                ;
        }
        public static IIdentityServerBuilder AddSnIdentityServerServices(this IIdentityServerBuilder builder)
        {
            return builder.AddCustomAuthorizeRequestValidator<SnAuthorizeRequestValidator>();
        }
    }
}

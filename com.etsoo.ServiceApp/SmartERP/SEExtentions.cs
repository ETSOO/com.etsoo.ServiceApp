using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP Service Application extension methods
    /// </summary>
    public static class SEExtentions
    {
        /// <summary>
        /// Add authorization service in extended applications
        /// </summary>
        /// <typeparam name="A">Generic applicaton type</typeparam>
        /// <typeparam name="C">Generic configuration type</typeparam>
        /// <param name="services">Service collection</param>
        /// <returns>Service collection</returns>
        public static IServiceCollection AddSEAuthService<A, C>(this IServiceCollection services)
            where A : ISEServiceApp
            where C : ServiceAppConfiguration
        {
            services.AddScoped<ISEAuthService>((sp) => new SEAuthService(
                sp.GetRequiredService<A>(),
                sp.GetRequiredService<C>(),
                sp.GetRequiredService<CurrentUserAccessor>(),
                sp.GetRequiredService<ILogger<SEAuthService>>(),
                sp.GetRequiredService<IHttpClientFactory>(),
                sp.GetRequiredService<IAuthService>()
            ));

            return services;
        }
    }
}

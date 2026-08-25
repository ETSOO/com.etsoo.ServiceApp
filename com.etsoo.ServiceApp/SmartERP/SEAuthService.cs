using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using com.etsoo.ServiceApp.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP Service Application authorization service
    /// 司友云ERP服务程序授权服务
    /// </summary>
    /// <typeparam name="C">Generic configuration type</typeparam>
    public class SEAuthService<C> : AuthServiceShared<NpgsqlConnection, ISEServiceApp<C>, CurrentUser>, ISEAuthService
        where C : ServiceAppConfiguration
    {
        public SEAuthService(
            ISEServiceApp<C> app,
            CurrentUserAccessor userAccessor,
            ILogger<SEAuthService<C>> logger,
            IHttpClientFactory clientFactory,
            IAuthService authService
        ) : base(app, userAccessor, logger, clientFactory, authService)
        {
        }
    }

    public static class SEAuthServiceExtensions
    {
        /// <summary>
        /// Add SmartERP Service Application authorization service
        /// </summary>
        /// <typeparam name="A">Generic applicaton type</typeparam>
        /// <typeparam name="C">Generic configuration type</typeparam>
        /// <param name="services">Service collection</param>
        /// <returns>Service collection</returns>
        public static IServiceCollection AddSEAuthService<A, C>(this IServiceCollection services)
            where A : ISEServiceApp<C>
            where C : ServiceAppConfiguration
        {
            services.AddScoped<ISEAuthService>((sp) => new SEAuthService<C>(
                sp.GetRequiredService<A>(),
                sp.GetRequiredService<CurrentUserAccessor>(),
                sp.GetRequiredService<ILogger<SEAuthService<C>>>(),
                sp.GetRequiredService<IHttpClientFactory>(),
                sp.GetRequiredService<IAuthService>()
            ));

            return services;
        }
    }
}

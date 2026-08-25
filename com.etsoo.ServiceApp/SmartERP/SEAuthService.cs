using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using com.etsoo.ServiceApp.Services;
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
}

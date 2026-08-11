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
    public class SEAuthService : AuthServiceShared<NpgsqlConnection, ISEServiceApp<ServiceAppConfiguration>, CurrentUser>, ISEAuthService
    {
        public SEAuthService(
            ISEServiceApp<ServiceAppConfiguration> app,
            CurrentUserAccessor userAccessor,
            ILogger<SEAuthService> logger,
            IHttpClientFactory clientFactory,
            CoreFramework.Authentication.IAuthService authService
        ) : base(app, userAccessor, logger, clientFactory, authService)
        {
        }
    }
}

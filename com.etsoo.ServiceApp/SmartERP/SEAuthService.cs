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
    public class SEAuthService : AuthServiceShared<ServiceAppConfiguration, NpgsqlConnection, ISEServiceApp, CurrentUser>, ISEAuthService
    {
        public SEAuthService(ISEServiceApp app, CurrentUserAccessor userAccessor, ILogger<SEAuthService> logger, IHttpClientFactory clientFactory)
            : base(app, userAccessor, logger, clientFactory)
        {
        }
    }
}

using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP Service Application Common service
    /// 司友云ERP服务程序通用服务
    /// </summary>
    public abstract class SEService : ServiceBase<ServiceAppConfiguration, NpgsqlConnection, ISEServiceApp, CurrentUser>, ISEService
    {
        protected SEService(ISEServiceApp app, CurrentUser? user, string flag, ILogger logger)
            : base(app, user, flag, logger)
        {
        }
    }
}

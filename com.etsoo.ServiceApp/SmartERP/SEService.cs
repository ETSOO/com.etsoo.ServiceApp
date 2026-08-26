using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Extensions.Logging;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP Service Application Common service
    /// 司友云ERP服务程序通用服务
    /// </summary>
    public abstract class SEService : ServiceBase<ISEServiceApp, CurrentUser>, ISEService
    {
        protected SEService(ISEServiceApp app, ServiceAppConfiguration configuration, CurrentUser? user, string flag, ILogger<SEService> logger)
            : base(app, configuration, user, flag, logger)
        {
        }
    }
}

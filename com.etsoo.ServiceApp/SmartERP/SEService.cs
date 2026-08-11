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
    /// <typeparam name="C">Generic configuration type</typeparam>
    public abstract class SEService<C> : ServiceBase<ISEServiceApp<C>, CurrentUser>, ISEService
        where C : ServiceAppConfiguration
    {
        protected SEService(ISEServiceApp<C> app, CurrentUser? user, string flag, ILogger<SEService<C>> logger)
            : base(app, user, flag, logger)
        {
        }
    }
}

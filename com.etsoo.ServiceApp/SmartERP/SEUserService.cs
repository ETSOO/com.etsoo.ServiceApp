using com.etsoo.CoreFramework.User;
using Microsoft.Extensions.Logging;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP Service Application Common user service
    /// 司友云ERP服务程序通用用户服务
    /// </summary>
    public abstract class SEUserService : SEService, ISEUserService
    {
        /// <summary>
        /// Current user
        /// 当前用户
        /// </summary>
        protected override CurrentUser User { get; }

        protected SEUserService(ISEServiceApp app, CurrentUser user, string flag, ILogger logger)
            : base(app, user, flag, logger)
        {
            User = user;
        }
    }
}

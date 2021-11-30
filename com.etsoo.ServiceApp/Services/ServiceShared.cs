using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.Services;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace com.etsoo.SmartERP.Services
{
    /// <summary>
    /// Shared service
    /// 共享的服务
    /// </summary>
    /// <typeparam name="R">Generic repository</typeparam>
    public abstract class ServiceShared<R> : ServiceBase<SqlConnection, R> where R : IRepoBase
    {
        /// <summary>
        /// Override App, change its type
        /// 重写App，修改类型
        /// </summary>
        protected override IServiceApp App { get; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="repo">Repository</param>
        /// <param name="logger">Logger</param>
        protected ServiceShared(IServiceApp app, R repo, ILogger logger)
            : base(app, repo, logger)
        {
            App = app;
        }
    }
}

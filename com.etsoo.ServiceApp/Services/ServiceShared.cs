using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.Services;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared service
    /// 共享的服务
    /// </summary>
    /// <typeparam name="A">Generic application</typeparam>
    /// <typeparam name="R">Generic repository</typeparam>
    public abstract class ServiceShared<A, R> : ServiceBase<SqlConnection, R, A>
        where A : IServiceApp
        where R : IRepoBase
    {
        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="repo">Repository</param>
        /// <param name="logger">Logger</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected ServiceShared(A app, R repo, ILogger logger, CancellationToken cancellationToken = default)
            : base(app, repo, logger, cancellationToken)
        {
        }
    }
}

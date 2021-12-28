using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared entity service
    /// 共享的实体服务
    /// </summary>
    /// <typeparam name="R">Generic repository</typeparam>
    /// <typeparam name="T">Generic id type</typeparam>
    public abstract class EntityServiceShared<R, T> : EntityServiceBase<SqlConnection, R, T> where R : IEntityRepo<T> where T : struct
    {
        /// <summary>
        /// Override App, change its type
        /// 重写App，修改类型
        /// </summary>
        protected override IServiceApp App { get; }

        /// <summary>
        /// Override User, change its type
        /// 重写User，修改类型
        /// </summary>
        protected override IServiceUser User { get; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="user">User</param>
        /// <param name="repo">Repository</param>
        /// <param name="logger">Logger</param>
        protected EntityServiceShared(IServiceApp app, IServiceUser user, R repo, ILogger logger)
            : base(app, user, repo, logger)
        {
            App = app;
            User = user;
        }
    }
}

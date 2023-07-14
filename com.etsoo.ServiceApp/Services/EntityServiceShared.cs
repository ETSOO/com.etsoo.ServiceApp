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
    /// <typeparam name="A">Generic application</typeparam>
    /// <typeparam name="U">Generic user</typeparam>
    /// <typeparam name="R">Generic repository</typeparam>
    /// <typeparam name="T">Generic id type</typeparam>
    public abstract class EntityServiceShared<A, U, R, T> : EntityServiceBase<SqlConnection, R, T, A>
        where A : IServiceApp
        where U : IServiceUser
        where R : IEntityRepo<T>
        where T : struct
    {
        /// <summary>
        /// Override App, change its type
        /// 重写App，修改类型
        /// </summary>
        protected new A App { get; }

        /// <summary>
        /// Override User, change its type
        /// 重写User，修改类型
        /// </summary>
        protected new U? User { get; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="repo">Repository</param>
        /// <param name="logger">Logger</param>
        protected EntityServiceShared(A app, R repo, ILogger logger)
            : base(app, repo, logger)
        {
            App = app;
            if (base.User == null)
            {
                User = default;
            }
            else if (base.User is U uUser)
            {

                User = uUser;
            }
            else
            {
                throw new ApplicationException("User Type Incompatible");
            }
        }
    }
}

using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.Services;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Sqlite service
    /// Sqlite 共享的服务
    /// </summary>
    /// <typeparam name="R">Generic repository</typeparam>
    public abstract class SqliteService<R> : ServiceBase<SqliteConnection, R> where R : IRepoBase
    {
        /// <summary>
        /// Override App, change its type
        /// 重写App，修改类型
        /// </summary>
        protected override ISqliteApp App { get; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="repo">Repository</param>
        /// <param name="logger">Logger</param>
        protected SqliteService(ISqliteApp app, R repo, ILogger logger)
            : base(app, repo, logger)
        {
            App = app;
        }
    }
}

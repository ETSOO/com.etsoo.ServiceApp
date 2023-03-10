using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.Sqlite;

namespace com.etsoo.ServiceApp.Repo
{
    /// <summary>
    /// Sqlite repository
    /// Sqlite 共享仓库
    /// </summary>
    public abstract class SqliteRepo : RepoBase<SqliteConnection, ISqliteApp>
    {
        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="flag">Flag</param>
        /// <param name="user">Current user</param>
        protected SqliteRepo(ISqliteApp app, string flag, IServiceUser? user = null)
            : base(app, flag, user)
        {
        }
    }
}

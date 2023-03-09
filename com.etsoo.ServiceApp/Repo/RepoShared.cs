using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.SqlClient;

namespace com.etsoo.ServiceApp.Repo
{
    /// <summary>
    /// Shared repository
    /// 共享仓库
    /// </summary>
    public abstract class RepoShared : RepoBase<SqlConnection>
    {
        /// <summary>
        /// Override App, change its type
        /// 重写App，修改类型
        /// </summary>
        protected readonly new IServiceApp App;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="flag">Flag</param>
        /// <param name="user">Current user</param>
        protected RepoShared(IServiceApp app, string flag, IServiceUser? user = null)
            : base(app, flag, user)
        {
            App = app;
        }
    }
}

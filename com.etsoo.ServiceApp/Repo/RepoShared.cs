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
    public abstract class RepoShared : RepoBase<SqlConnection, IServiceApp>
    {
        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="flag">Flag</param>
        /// <param name="user">Current user</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected RepoShared(IServiceApp app, string flag, IServiceUser? user = null, CancellationToken cancellationToken = default)
            : base(app, flag, user, cancellationToken)
        {
        }
    }
}

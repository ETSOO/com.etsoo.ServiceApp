using com.etsoo.CoreFramework.Repositories;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using Microsoft.Data.SqlClient;

namespace com.etsoo.ServiceApp.Repo
{
    /// <summary>
    /// Shared entity repository
    /// 共享实体仓库
    /// </summary>
    public abstract class EntityRepoShared<T> : EntityRepo<SqlConnection, T> where T : struct
    {
        /// <summary>
        /// Override App, change its type
        /// 重写App，修改类型
        /// </summary>
        protected new readonly IServiceApp App;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="flag">Flag</param>
        protected EntityRepoShared(IServiceApp app, string flag, IServiceUser? user)
            : base(app, flag, user)
        {
            App = app;
        }
    }
}

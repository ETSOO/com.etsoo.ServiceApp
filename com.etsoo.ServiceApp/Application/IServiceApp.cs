using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using System.Data.Common;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// SmartERP service base application interface
    /// SmartERP服务基础程序接口
    /// </summary>
    /// <typeparam name="C">Connection</typeparam>
    public interface IServiceBaseApp<C> : ICoreApplication<C> where C : DbConnection
    {
        /// <summary>
        /// Application configuration
        /// 程序配置
        /// </summary>
        new IServiceAppConfiguration Configuration { get; }

        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        IAuthService AuthService { get; init; }

        /// <summary>
        /// Configuration section
        /// 配置区块
        /// </summary>
        IConfigurationSection Section { get; init; }
    }

    /// <summary>
    /// SmartERP service application interface
    /// SmartERP服务程序接口
    /// </summary>
    public interface IServiceApp : IServiceBaseApp<SqlConnection> { }

    /// <summary>
    /// Sqlite service application interface
    /// Sqlite服务程序接口
    /// </summary>
    public interface ISqliteApp : IServiceBaseApp<SqliteConnection> { }
}

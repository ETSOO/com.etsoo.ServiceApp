using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization.Metadata;

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
        IAuthService? AuthService { get; init; }

        /// <summary>
        /// Exchange data encryption
        /// 交换数据加密
        /// </summary>
        /// <param name="plainText">Plain text</param>
        /// <returns>Result</returns>
        string ExchangeData(string plainText);

        /// <summary>
        /// Async exchange object data encryption
        /// 异步交换对象数据加密
        /// </summary>
        /// <typeparam name="T">Generic object type</typeparam>
        /// <param name="obj">Object</param>
        /// <returns>Result</returns>
        [RequiresDynamicCode("ExchangeDataAsync 'T' may require dynamic access otherwise can break functionality when trimming application code")]
        [RequiresUnreferencedCode("ExchangeDataAsync 'T' may require dynamic access otherwise can break functionality when trimming application code")]
        Task<string> ExchangeDataAsync<T>(T obj);

        /// <summary>
        /// Async exchange object data encryption
        /// 异步交换对象数据加密
        /// </summary>
        /// <typeparam name="T">Generic object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="typeInfo">Json type info</param>
        /// <returns>Result</returns>
        Task<string> ExchangeDataAsync<T>(T obj, JsonTypeInfo<T> typeInfo);
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

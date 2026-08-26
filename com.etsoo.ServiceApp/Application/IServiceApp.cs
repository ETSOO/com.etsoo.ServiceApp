using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Models;
using System.Data.Common;
using System.Text.Json.Serialization.Metadata;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// SmartERP service base application interface
    /// Using global using to delcar alias instead of creating new extended interfaces
    /// SmartERP服务基础程序接口
    /// </summary>
    /// <typeparam name="C">Connection</typeparam>
    public interface IServiceApp<out C> : ICoreApplication<C>
        where C : DbConnection
    {
        /// <summary>
        /// Get exchange key
        /// </summary>
        /// <returns>Result</returns>
        string GetExchangeKey();

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
        /// <param name="typeInfo">Json type info</param>
        /// <returns>Result</returns>
        Task<string> ExchangeDataAsync<T>(T obj, JsonTypeInfo<T> typeInfo);

        /// <summary>
        /// Sign action data
        /// 签名动作数据
        /// </summary>
        /// <param name="action">Action name</param>
        /// <param name="targetId">Target ID</param>
        /// <returns>Result</returns>
        AppActionData SignAction(string action, long targetId);
    }
}

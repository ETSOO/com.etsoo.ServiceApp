using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Models;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using com.etsoo.Utils;
using com.etsoo.Utils.Crypto;
using Microsoft.Extensions.DependencyInjection;
using System.Data.Common;
using System.Text.Json.Serialization.Metadata;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Common service application
    /// 通用服务程序
    /// </summary>
    /// <typeparam name="C">Generic database type</typeparam>
    public abstract class ServiceCommonApp<C> : CoreApplication<C>, IServiceApp<C>
        where C : DbConnection
    {
        private readonly ServiceAppConfiguration _config;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services</param>
        /// <param name="db">Database</param>
        /// <param name="configuration">Configuration</param>
        /// <param name="modelValidated">Is model validated</param>
        public ServiceCommonApp(IServiceCollection services, IDatabase<C> db, ServiceAppConfiguration configuration, bool modelValidated = false)
            : base(db, configuration.PrivateKey, modelValidated)
        {
            _config = configuration;
        }

        public override void AddSystemParameters(IUserToken user, IDbParameters parameters)
        {
            // Change to int from default string parameter
            // Also possible to change global names
            parameters.Add(Constants.CurrentUserField, user.IdInt);
            parameters.Add(Constants.CurrentOrgField, user.OrganizationInt);
        }

        /// <summary>
        /// Get exchange key
        /// </summary>
        /// <returns>Result</returns>
        public virtual string GetExchangeKey()
        {
            return GetExchangeKey(_config.AppId, _config.AppSecret);
        }

        /// <summary>
        /// Exchange data encryption
        /// 交换数据加密
        /// </summary>
        /// <param name="plainText">Plain text</param>
        /// <returns>Result</returns>
        public string ExchangeData(string plainText)
        {
            return CryptographyUtils.AESEncrypt(plainText, GetExchangeKey(), 10);
        }

        /// <summary>
        /// Async exchange object data encryption
        /// 异步交换对象数据加密
        /// </summary>
        /// <typeparam name="T">Generic object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="typeInfo">Json type info</param>
        /// <returns>Result</returns>
        public async Task<string> ExchangeDataAsync<T>(T obj, JsonTypeInfo<T> typeInfo)
        {
            var json = await SharedUtils.JsonSerializeAsync(obj, typeInfo);
            return ExchangeData(json);
        }

        /// <summary>
        /// Sign action data
        /// 签名动作数据
        /// </summary>
        /// <param name="action">Action name</param>
        /// <param name="targetId">Target ID</param>
        /// <returns>Result</returns>
        public AppActionData SignAction(string action, long targetId)
        {
            var data = new AppActionData
            {
                AppId = _config.AppId,
                AppKey = _config.AppKey,
                Action = action,
                TargetId = targetId
            };

            data.Sign = data.SignWith(_config.AppSecret);

            return data;
        }
    }
}
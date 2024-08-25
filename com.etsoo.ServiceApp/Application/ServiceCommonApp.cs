using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using com.etsoo.Utils;
using com.etsoo.Utils.Crypto;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization.Metadata;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Common service application
    /// 通用服务程序
    /// </summary>
    /// <typeparam name="C">Generic database type</typeparam>
    public abstract class ServiceCommonApp<S, C> : CoreApplication<S, C>, IServiceBaseApp<S, C>
        where S : ServiceAppConfiguration
        where C : DbConnection
    {
        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        public IAuthService? AuthService { get; init; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services</param>
        /// <param name="configuration">Configuration</param>
        /// <param name="db">Database</param>
        /// <param name="jwtSettings">JWT settings</param>
        /// <param name="events">Events</param>
        /// <param name="modelValidated">Is model validated</param>
        public ServiceCommonApp(IServiceCollection services, S configuration, IDatabase<C> db, JwtSettings? jwtSettings, JwtBearerEvents? events = null, bool modelValidated = false)
            : base(configuration, db, modelValidated)
        {
            if (jwtSettings != null)
            {
                AuthService = new JwtService(services, jwtSettings, events);
            }
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
            return GetExchangeKey(Configuration.AppId, Configuration.AppSecret);
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
        /// <returns>Result</returns>
        [RequiresDynamicCode("ExchangeDataAsync 'T' may require dynamic access otherwise can break functionality when trimming application code")]
        [RequiresUnreferencedCode("ExchangeDataAsync 'T' may require dynamic access otherwise can break functionality when trimming application code")]
        public async Task<string> ExchangeDataAsync<T>(T obj)
        {
            var json = await SharedUtils.JsonSerializeAsync(obj, SharedUtils.JsonDefaultSerializerOptions);
            return ExchangeData(json);
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
    }
}
using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using com.etsoo.Utils;
using com.etsoo.Utils.Crypto;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Data.Common;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Common service application
    /// 通用服务程序
    /// </summary>
    /// <typeparam name="C">Generic database type</typeparam>
    public abstract record ServiceCommonApp<C> : CoreApplication<C>, IServiceBaseApp<C> where C : DbConnection
    {
        readonly string _encryptionKey;

        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        public IAuthService? AuthService { get; init; }

        /// <summary>
        /// Configuration section
        /// 配置区块
        /// </summary>
        public IConfigurationSection Section { get; init; }

        /// <summary>
        /// Application configuration localized
        /// 本地化程序配置
        /// </summary>
        public new IServiceAppConfiguration Configuration => (IServiceAppConfiguration)base.Configuration;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services</param>
        /// <param name="configurationSection">Configuration</param>
        /// <param name="init">Init</param>
        /// <param name="unsealData">Unseal handler</param>
        /// <param name="events">JWT events</param>
        public ServiceCommonApp(
            IServiceCollection services,
            IConfigurationSection configurationSection,
            (IAppConfiguration configuration, IDatabase<C> db) init,
            Func<string, string, string>? unsealData,
            JwtBearerEvents? events = null) : base(init)
        {
            // Hold the section
            Section = configurationSection;

            string? encryptionKey;

            var jwtSection = configurationSection.GetSection("Jwt");
            if (jwtSection.Exists())
            {
                // Init the authentication service
                AuthService = new JwtService(services, jwtSection, unsealData, events: events);

                encryptionKey = jwtSection.GetSection("EncryptionKey").Get<string>();
            }
            else
            {
                encryptionKey = configurationSection.GetSection("Jwt-EncryptionKey").Get<string>();
            }

            if (string.IsNullOrEmpty(encryptionKey))
            {
                throw new Exception("No EncryptionKey configured");
            }

            _encryptionKey = unsealData == null ? encryptionKey : unsealData("Jwt-EncryptionKey", encryptionKey);
        }

        /// <summary>
        /// Override add system parameters
        /// 重写添加系统参数
        /// </summary>
        /// <param name="user">Current user</param>
        /// <param name="parameters">Parameers</param>
        public override void AddSystemParameters(IServiceUser user, IDbParameters parameters)
        {
            // Change to int from default string parameter
            // Also possible to change global names
            parameters.Add(Constants.CurrentUserField, user.IdInt);
            parameters.Add(Constants.CurrentOrgField, user.OrganizationInt);
        }

        /// <summary>
        /// Exchange data encryption
        /// 交换数据加密
        /// </summary>
        /// <param name="plainText">Plain text</param>
        /// <returns>Result</returns>
        public string ExchangeData(string plainText)
        {
            return CryptographyUtils.AESEncrypt(plainText, GetExchangeKey(_encryptionKey, Configuration.ServiceId), 10);
        }

        /// <summary>
        /// Async exchange object data encryption
        /// 异步交换对象数据加密
        /// </summary>
        /// <typeparam name="T">Generic object type</typeparam>
        /// <param name="obj">Object</param>
        /// <returns>Result</returns>
        public async Task<string> ExchangeDataAsync<T>(T obj)
        {
            var json = await SharedUtils.JsonSerializeAsync(obj, SharedUtils.JsonDefaultSerializerOptions);
            return ExchangeData(json);
        }
    }
}
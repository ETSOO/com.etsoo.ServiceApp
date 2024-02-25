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
        /// Setup application
        /// 设置应用程序
        /// </summary>
        /// <param name="section">Configuration section</param>
        /// <param name="unsealData">Unseal data function</param>
        /// <param name="creator">Configuration and Database creator function</param>
        /// <returns>Result</returns>
        /// <exception cref="Exception">No configuration section</exception>
        protected static (S, IDatabase<C>) SetupApp(IConfiguration section, Func<string, string, string>? unsealData, Func<IConfigurationSection, string, (S? configuration, IDatabase<C> db)> creator)
        {
            // App configuration
            var data = section.GetSection("Configuration");
            if (!data.Exists())
            {
                throw new Exception("Configuration section not found");
            }

            // Database
            var field = "ConnectionString";
            var csRaw = section.GetSection(field).Value ?? section.GetConnectionString(data.GetSection(nameof(ServiceAppConfiguration.Name)).Value ?? "SmartERPService");
            var connectionString = CryptographyUtils.UnsealData(field, csRaw, unsealData);

            var (config, db) = creator(data, connectionString);
            if (config == null)
            {
                throw new Exception("Configuration creation failed");
            }

            config.UnsealData(unsealData);

            // Return
            return (config, db);
        }

        /// <summary>
        /// Setup application authorization
        /// 设置应用授权
        /// </summary>
        /// <param name="services">Services</param>
        /// <param name="section">Configuration section</param>
        /// <param name="unsealData">Unseal data handler</param>
        /// <param name="events">JWT events</param>
        /// <param name="creator">Jwt settings creator function</param>
        /// <returns>Result</returns>
        /// <exception cref="Exception">No EncryptionKey configured exception</exception>
        protected static (string encryptionKey, IAuthService? authService) SetupAuth(IServiceCollection services, IConfiguration section, Func<string, string, string>? unsealData, JwtBearerEvents? events, Func<IConfigurationSection, JwtSettings?> creator)
        {
            string? encryptionKey = null;
            IAuthService? authService = null;

            var jwt = section.GetSection("Jwt");
            if (jwt.Exists())
            {
                var settings = creator(jwt);
                if (settings == null)
                {
                    throw new Exception("JWT settings creation failed");
                }

                authService = new JwtService(services, settings, unsealData, events: events);
                encryptionKey = settings.EncryptionKey;
            }
            else
            {
                authService = null;
                encryptionKey = section.GetSection("Jwt-EncryptionKey").Value;
            }

            if (string.IsNullOrEmpty(encryptionKey))
            {
                throw new Exception("No EncryptionKey configured");
            }

            encryptionKey = unsealData == null ? encryptionKey : unsealData(nameof(encryptionKey), encryptionKey);

            return (encryptionKey, authService);
        }

        readonly string _encryptionKey;

        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        public IAuthService? AuthService { get; init; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="init">Init</param>
        /// <param name="auth">Authorization</param>
        /// <param name="modelValidated">Model validated or not</param>
        public ServiceCommonApp(
            (S configuration, IDatabase<C> db) init,
            (string encryptionKey, IAuthService? authService) auth,
            bool modelValidated = false
        ) : base(init, modelValidated)
        {
            // Init auth
            (_encryptionKey, AuthService) = auth;
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
using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.Utils.Crypto;
using com.etsoo.Utils.Database;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Text;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// SmartERP service application
    /// 司友云ERP服务程序
    /// </summary>
    public record ServiceApp : CoreApplication<SqlConnection>, IServiceApp
    {
        /// <summary>
        /// Service name
        /// </summary>
        protected static string ServiceName = "SmartERPService";

        private static string DoSecretData(string input)
        {
            input = input.Replace("-", "");
            input = (char)((input[0] + input.Last()) / 2) + input[2..] + ServiceName;
            return input;
        }

        /// <summary>
        /// Secret data, keep it safe
        /// Powershell: [System.Environment]::SetEnvironmentVariable('ServiceName', [guid]::NewGuid().Guid,[System.EnvironmentVariableTarget]::Machine)
        /// </summary>
        private static readonly string secretData = DoSecretData(Environment.GetEnvironmentVariable(ServiceName, EnvironmentVariableTarget.Machine) ?? Guid.NewGuid().ToString());

        /// <summary>
        /// Unseal data
        /// 解密信息
        /// </summary>
        /// <param name="input">Base64 input data</param>
        /// <returns>Unsealed data</returns>
        public static string UnsealData(string input)
        {
            return Encoding.UTF8.GetString(CryptographyUtils.AESDecrypt(Convert.FromBase64String(input), secretData));
        }

        private static (ServiceAppConfiguration, IDatabase<SqlConnection>) Create(IConfigurationSection section, bool modelValidated)
        {
            // App configuration
            var config = new ServiceAppConfiguration(section.GetSection("Configuration"), UnsealData, modelValidated);

            // Database
            var connectionString = UnsealData(section.GetValue<string>("ConnectionString"));
            var snakeNaming = section.GetValue<bool>("SnakeNaming", false);
            var db = new SqlServerDatabase(connectionString, snakeNaming);

            // Return
            return (config, db);
        }

        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        public IAuthService AuthService { get; init; }

        /// <summary>
        /// Configuration section
        /// 配置区块
        /// </summary>
        public IConfigurationSection Section { get; init; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services dependency injection</param>
        /// <param name="configurationSection">Configuration section</param>
        /// <param name="sslOnly">SSL only</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        public ServiceApp(IServiceCollection services, IConfigurationSection configurationSection, bool sslOnly = true, bool modelValidated = false)
            : base(Create(configurationSection, modelValidated))
        {
            // Init the authentication service
            AuthService = new JwtService(services,
                sslOnly,
                configurationSection.GetSection("Jwt"), UnsealData);

            // Hold the section
            Section = configurationSection;
        }

        /// <summary>
        /// Application configuration localized
        /// 本地化程序配置
        /// </summary>
        public new IServiceAppConfiguration Configuration => (IServiceAppConfiguration)base.Configuration;

        /// <summary>
        /// Override add system parameters
        /// 重写添加系统参数
        /// </summary>
        /// <param name="user">Current user</param>
        /// <param name="parameters">Parameers</param>
        public override void AddSystemParameters(IServiceUser user, DynamicParameters parameters)
        {
            // Change to int from default string parameter
            // Also possible to change global names
            parameters.Add("CurrentUser", user.IdInt);
            if (user.OrganizationInt != null)
                parameters.Add("CurrentOrg", user.OrganizationInt);
        }
    }
}

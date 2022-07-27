using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Sqlite application
    /// Sqlite 程序
    /// </summary>
    public record SqliteApp : CoreApplication<SqliteConnection>, ISqliteApp
    {
        private static (ServiceAppConfiguration, IDatabase<SqliteConnection>) Create(IConfigurationSection section, bool modelValidated, Func<string, string> unsealData)
        {
            // App configuration
            var config = new ServiceAppConfiguration(section.GetSection("Configuration"), unsealData, modelValidated);

            // Database
            var connectionString = unsealData(section.GetValue<string>("ConnectionString"));
            var snakeNaming = section.GetValue("SnakeNaming", false);
            var db = new SqliteDatabase(connectionString, snakeNaming);

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
        /// <param name="unsealData">Unseal data delegate</param>
        /// <param name="sslOnly">SSL only</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        public SqliteApp(IServiceCollection services, IConfigurationSection configurationSection, Func<string, string> unsealData, bool sslOnly = true, bool modelValidated = false)
            : base(Create(configurationSection, modelValidated, unsealData))
        {
            // Init the authentication service
            AuthService = new JwtService(services,
                sslOnly,
                configurationSection.GetSection("Jwt"), unsealData);

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
            parameters.Add(Constants.CurrentUserField, user.IdInt);
            if (user.OrganizationInt != null)
                parameters.Add(Constants.CurrentOrgField, user.OrganizationInt);
        }
    }
}

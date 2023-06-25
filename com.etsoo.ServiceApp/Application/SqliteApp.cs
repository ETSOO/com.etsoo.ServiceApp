using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using com.etsoo.Utils.Crypto;
using Microsoft.AspNetCore.Authentication.JwtBearer;
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
        private static (ServiceAppConfiguration, IDatabase<SqliteConnection>) Create(IConfigurationSection section, bool modelValidated, Func<string, string, string>? unsealData)
        {
            // App configuration
            var config = new ServiceAppConfiguration(section.GetSection("Configuration"), unsealData, modelValidated);

            // Database
            var field = "ConnectionString";
            var connectionString = CryptographyUtils.UnsealData(field, section.GetValue<string>(field), unsealData);
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
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        /// <param name="events">JWT events</param>
        public SqliteApp(IServiceCollection services, IConfigurationSection configurationSection, Func<string, string, string>? unsealData, bool modelValidated = false, JwtBearerEvents? events = null)
            : base(Create(configurationSection, modelValidated, unsealData))
        {
            // Init the authentication service
            AuthService = new JwtService(services, configurationSection.GetSection("Jwt"), unsealData, events: events);

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
        public override void AddSystemParameters(IServiceUser user, IDbParameters parameters)
        {
            // Change to int from default string parameter
            // Also possible to change global names
            parameters.Add(Constants.CurrentUserField, user.IdInt);
            parameters.Add(Constants.CurrentOrgField, user.OrganizationInt);
        }
    }
}

using com.etsoo.Database;
using com.etsoo.Utils.Crypto;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// SmartERP service application
    /// 司友云ERP服务程序
    /// </summary>
    public record ServiceApp : ServiceCommonApp<SqlConnection>, IServiceApp
    {
        private static (ServiceAppConfiguration, IDatabase<SqlConnection>) Create(IConfigurationSection section, bool modelValidated, Func<string, string, string>? unsealData)
        {
            // App configuration
            var config = new ServiceAppConfiguration(section.GetSection("Configuration"), unsealData, modelValidated);

            // Database
            var field = "ConnectionString";
            var connectionString = CryptographyUtils.UnsealData(field, section.GetValue<string>(field), unsealData);
            var snakeNaming = section.GetValue("SnakeNaming", false);
            var db = new SqlServerDatabase(connectionString, snakeNaming);

            // Return
            return (config, db);
        }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services dependency injection</param>
        /// <param name="configurationSection">Configuration section</param>
        /// <param name="unsealData">Unseal data delegate</param>
        /// <param name="sslOnly">SSL only</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        /// <param name="events">JWT events</param>
        public ServiceApp(IServiceCollection services, IConfigurationSection configurationSection, Func<string, string, string>? unsealData, bool modelValidated = false, JwtBearerEvents? events = null)
            : base(services, configurationSection, Create(configurationSection, modelValidated, unsealData), unsealData, events)
        {
        }
    }
}

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
    public record SqliteApp : ServiceCommonApp<SqliteConnection>, ISqliteApp
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
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services dependency injection</param>
        /// <param name="configurationSection">Configuration section</param>
        /// <param name="unsealData">Unseal data delegate</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        /// <param name="events">JWT events</param>
        public SqliteApp(IServiceCollection services, IConfigurationSection configurationSection, Func<string, string, string>? unsealData, bool modelValidated = false, JwtBearerEvents? events = null)
            : base(services, configurationSection, Create(configurationSection, modelValidated, unsealData), unsealData, events)
        {
        }
    }
}

using com.etsoo.Database;
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
    /// <remarks>
    /// Constructor
    /// 构造函数
    /// </remarks>
    /// <param name="services">Services dependency injection</param>
    /// <param name="configurationSection">Configuration section</param>
    /// <param name="unsealData">Unseal data delegate</param>
    /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
    /// <param name="events">JWT events</param>
    public class SqliteApp(IServiceCollection services, IConfigurationSection configurationSection, Func<string, string, string>? unsealData, bool modelValidated = false, JwtBearerEvents? events = null)
        : ServiceCommonApp<SqliteConnection>(SetupApp(configurationSection, modelValidated, unsealData, connectionString => new SqliteDatabase(connectionString)), SetupAuth(services, configurationSection, unsealData, events)), ISqliteApp
    {
    }
}

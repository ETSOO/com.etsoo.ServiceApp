using com.etsoo.Database;
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
    /// <remarks>
    /// Constructor
    /// 构造函数
    /// </remarks>
    /// <param name="services">Services dependency injection</param>
    /// <param name="configurationSection">Configuration section</param>
    /// <param name="unsealData">Unseal data delegate</param>
    /// <param name="sslOnly">SSL only</param>
    /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
    /// <param name="events">JWT events</param>
    public class ServiceApp(IServiceCollection services, IConfigurationSection configurationSection, Func<string, string, string>? unsealData, bool modelValidated = false, JwtBearerEvents? events = null)
        : ServiceCommonApp<SqlConnection>(SetupApp(configurationSection, modelValidated, unsealData, connectionString => new SqlServerDatabase(connectionString)), SetupAuth(services, configurationSection, unsealData, events)), IServiceApp
    {
    }
}

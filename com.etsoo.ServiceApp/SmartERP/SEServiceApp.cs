using com.etsoo.CoreFramework.Authentication;
using com.etsoo.Database;
using com.etsoo.ServiceApp.Application;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP service application
    /// 司友云ERP服务程序
    /// </summary>
    public class SEServiceApp : ServiceCommonApp<ServiceAppConfiguration, NpgsqlConnection>, ISEServiceApp
    {
        public SEServiceApp(IServiceCollection services, ServiceAppConfiguration configuration, IDatabase<NpgsqlConnection> db, JwtSettings? jwtSettings, JwtBearerEvents? events = null, bool modelValidated = false, int? appId = null)
            : base(services, configuration, db, jwtSettings, events, modelValidated)
        {
            if (appId.HasValue)
            {
                AppId = appId.Value;
            }
        }
    }
}

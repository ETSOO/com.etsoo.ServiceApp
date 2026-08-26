using com.etsoo.Database;
using com.etsoo.ServiceApp.Application;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP service application
    /// 司友云ERP服务程序
    /// </summary>
    public class SEServiceApp : ServiceCommonApp<NpgsqlConnection>, ISEServiceApp
    {
        public SEServiceApp(IServiceCollection services, IDatabase<NpgsqlConnection> db, ServiceAppConfiguration configuration, bool modelValidated = false, int? appId = null)
            : base(services, db, configuration, modelValidated)
        {
            if (appId.HasValue)
            {
                AppId = appId.Value;
            }
        }
    }
}

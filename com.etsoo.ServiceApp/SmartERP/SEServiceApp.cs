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
    /// <typeparam name="C">Generic configuration type</typeparam>
    public class SEServiceApp<C> : ServiceCommonApp<C, NpgsqlConnection>, ISEServiceApp<C>
        where C : ServiceAppConfiguration
    {
        public SEServiceApp(IServiceCollection services, C configuration, IDatabase<NpgsqlConnection> db, bool modelValidated = false, int? appId = null)
            : base(services, configuration, db, modelValidated)
        {
            if (appId.HasValue)
            {
                AppId = appId.Value;
            }
        }
    }
}

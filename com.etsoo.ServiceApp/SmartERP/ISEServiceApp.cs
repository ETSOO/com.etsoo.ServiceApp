using com.etsoo.ServiceApp.Application;
using Npgsql;

namespace com.etsoo.ServiceApp.SmartERP
{
    /// <summary>
    /// SmartERP service application interface
    /// 司友云ERP服务程序接口
    /// </summary>
    /// <typeparam name="C">Generic configuration type</typeparam>
    public interface ISEServiceApp<out C> : IServiceApp<C, NpgsqlConnection>
        where C : ServiceAppConfiguration
    {
    }
}

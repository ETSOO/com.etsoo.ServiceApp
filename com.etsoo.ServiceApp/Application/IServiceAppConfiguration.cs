using com.etsoo.CoreFramework.Application;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// SmartERP service application configuration interface
    /// SmartERP服务程序配置接口
    /// </summary>
    public interface IServiceAppConfiguration : IAppConfiguration
    {
        /// <summary>
        /// Service id
        /// 服务编号
        /// </summary>
        int ServiceId { get; }
    }
}

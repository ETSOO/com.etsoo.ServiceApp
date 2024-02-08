using com.etsoo.CoreFramework.Application;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Service application configuration items
    /// 服务程序配置项
    /// </summary>
    public record ServiceAppConfigurationItems : AppConfigurationItems
    {
        /// <summary>
        /// Service id
        /// 服务编号
        /// </summary>
        public int ServiceId { get; init; }
    }
}
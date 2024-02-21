using com.etsoo.CoreFramework.Application;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Service application configuration
    /// 服务程序配置
    /// </summary>
    public record ServiceAppConfiguration : AppConfiguration
    {
        /// <summary>
        /// Service id
        /// 服务编号
        /// </summary>
        public int ServiceId { get; init; }
    }
}

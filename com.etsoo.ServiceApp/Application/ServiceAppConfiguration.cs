using com.etsoo.CoreFramework.Application;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Service application configuration
    /// 服务程序配置
    /// </summary>
    public record ServiceAppConfiguration : AppConfiguration, IServiceAppConfiguration
    {
        /// <summary>
        /// Service id
        /// 服务编号
        /// </summary>
        public int ServiceId { get; init; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="items">Configuration items</param>
        /// <param name="secureManager">Secure manager</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        public ServiceAppConfiguration(ServiceAppConfigurationItems items, Func<string, string, string>? secureManager, bool modelValidated = false) : base(items, secureManager, modelValidated)
        {
            ServiceId = items.ServiceId;
        }
    }
}

using com.etsoo.CoreFramework.Application;
using Microsoft.Extensions.Configuration;

namespace com.etsoo.ServiceApp.Application
{
    public record ServiceAppConfiguration : AppConfiguration, IServiceAppConfiguration
    {
        /// <summary>
        /// Service id
        /// 服务编号
        /// </summary>
        public int ServiceId { get; }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="section">Configuration section</param>
        /// <param name="secureManager">Secure manager</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        public ServiceAppConfiguration(IConfigurationSection section, Func<string, string> secureManager, bool modelValidated = false) : base(section, secureManager, modelValidated)
        {
            ServiceId = section.GetValue<int>("ServiceId");
        }
    }
}

using com.etsoo.CoreFramework.Application;
using Microsoft.Extensions.Configuration;

namespace com.etsoo.ServiceApp
{
    public record ServiceAppConfiguration : AppConfiguration, IServiceAppConfiguration
    {
        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="section">Configuration section</param>
        /// <param name="secureManager">Secure manager</param>
        /// <param name="modelValidated">Model DataAnnotations are validated or not</param>
        public ServiceAppConfiguration(IConfigurationSection section, Func<string, string> secureManager, bool modelValidated = false) : base(section, secureManager, modelValidated)
        {
        }
    }
}

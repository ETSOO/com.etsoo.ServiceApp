using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// SmartERP service application interface
    /// SmartERP服务程序接口
    /// </summary>
    public interface IServiceApp : ICoreApplication<SqlConnection>
    {
        /// <summary>
        /// Application configuration
        /// 程序配置
        /// </summary>
        new IServiceAppConfiguration Configuration { get; }

        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        IAuthService AuthService { get; init; }

        /// <summary>
        /// Configuration section
        /// 配置区块
        /// </summary>
        IConfigurationSection Section { get; init; }
    }
}

using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Authentication;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Data.Common;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Common service application
    /// 通用服务程序
    /// </summary>
    /// <typeparam name="C">Generic database type</typeparam>
    public abstract record ServiceCommonApp<C> : CoreApplication<C>, IServiceBaseApp<C> where C : DbConnection
    {
        /// <summary>
        /// Authentication service
        /// 验证服务
        /// </summary>
        public IAuthService? AuthService { get; init; }

        /// <summary>
        /// Configuration section
        /// 配置区块
        /// </summary>
        public IConfigurationSection Section { get; init; }

        /// <summary>
        /// Application configuration localized
        /// 本地化程序配置
        /// </summary>
        public new IServiceAppConfiguration Configuration => (IServiceAppConfiguration)base.Configuration;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="services">Services</param>
        /// <param name="configurationSection">Configuration</param>
        /// <param name="init">Init</param>
        /// <param name="unsealData">Unseal handler</param>
        /// <param name="events">JWT events</param>
        public ServiceCommonApp(
            IServiceCollection services,
            IConfigurationSection configurationSection,
            (IAppConfiguration configuration, IDatabase<C> db) init,
            Func<string, string, string>? unsealData,
            JwtBearerEvents? events = null) : base(init)
        {
            // Hold the section
            Section = configurationSection;

            var jwtSection = configurationSection.GetSection("Jwt");
            if (jwtSection.Exists())
            {
                // Init the authentication service
                AuthService = new JwtService(services, configurationSection.GetSection("Jwt"), unsealData, events: events);
            }
        }

        /// <summary>
        /// Override add system parameters
        /// 重写添加系统参数
        /// </summary>
        /// <param name="user">Current user</param>
        /// <param name="parameters">Parameers</param>
        public override void AddSystemParameters(IServiceUser user, IDbParameters parameters)
        {
            // Change to int from default string parameter
            // Also possible to change global names
            parameters.Add(Constants.CurrentUserField, user.IdInt);
            parameters.Add(Constants.CurrentOrgField, user.OrganizationInt);
        }
    }
}

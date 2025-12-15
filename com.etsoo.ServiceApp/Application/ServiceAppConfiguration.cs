using com.etsoo.CoreFramework.Application;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;

namespace com.etsoo.ServiceApp.Application
{
    /// <summary>
    /// Service application configuration
    /// 服务程序配置
    /// </summary>
    public record ServiceAppConfiguration : AppConfiguration
    {
        /// <summary>
        /// Application web url
        /// 程序网页地址
        /// </summary>
        [Url]
        public string AppWebUrl { get; init; } = "http://localhost";

        /// <summary>
        /// Application Api url
        /// 程序接口地址
        /// </summary>
        [Url]
        public string AppApiUrl { get; init; } = "http://localhost/api";

        /// <summary>
        /// Application id
        /// 程序编号
        /// </summary>
        [Required]
        public int AppId { get; init; }

        /// <summary>
        /// Application key
        /// 程序键名
        /// </summary>
        public string AppKey { get; init; } = string.Empty;

        /// <summary>
        /// Application secret
        /// 程序密钥
        /// </summary>
        [Required]
        public string AppSecret { get; init; } = default!;

        /// <summary>
        /// Permission scopes, space-delimited
        /// 权限范围，空格分隔
        /// </summary>
        public string Scopes { get; init; } = "core";

        /// <summary>
        /// Authorized redirect URIs for the server side application
        /// </summary>
        [Url]
        public string? ServerRedirectUrl { get; init; }

        /// <summary>
        /// Authorized redirect URIs for the script side application
        /// </summary>
        [Url]
        public string? ScriptRedirectUrl { get; init; }

        /// <summary>
        /// Authorization failure URL
        /// 授权失败地址
        /// </summary>
        [Url]
        public string? AuthFailureUrl { get; init; }

        /// <summary>
        /// Authorization success URL
        /// 授权成功地址
        /// </summary>
        [Url]
        public string? AuthSuccessUrl { get; init; }
    }

    [OptionsValidator]
    public partial class ValidateServiceAppConfiguration : IValidateOptions<ServiceAppConfiguration>
    {
    }
}

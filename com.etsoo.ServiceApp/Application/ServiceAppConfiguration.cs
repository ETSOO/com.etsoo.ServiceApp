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
        /// Application id
        /// 程序编号
        /// </summary>
        [Required]
        public int AppId { get; set; }

        /// <summary>
        /// Application key
        /// 程序键名
        /// </summary>
        public string AppKey { get; set; } = string.Empty;

        /// <summary>
        /// Application secret
        /// 程序密钥
        /// </summary>
        [Required]
        public string AppSecret { get; set; } = default!;

        /// <summary>
        /// Core API endpoint
        /// 核心接口地址
        /// </summary>
        [Url]
        [Required]
        public string Endpoint { get; set; } = default!;

        /// <summary>
        /// Permission scopes, space-delimited
        /// 权限范围，空格分隔
        /// </summary>
        public string Scopes { get; set; } = "core";

        /// <summary>
        /// Authorized redirect URIs for the server side application
        /// </summary>
        [Url]
        public string? ServerRedirectUrl { get; set; }

        /// <summary>
        /// Authorized redirect URIs for the script side application
        /// </summary>
        [Url]
        public string? ScriptRedirectUrl { get; set; }

        /// <summary>
        /// Authorization failure URL
        /// 授权失败地址
        /// </summary>
        [Url]
        public string? AuthFailureUrl { get; set; }

        /// <summary>
        /// Authorization success URL
        /// 授权成功地址
        /// </summary>
        [Url]
        public string? AuthSuccessUrl { get; set; }
    }

    [OptionsValidator]
    public partial class ValidateServiceAppConfiguration : IValidateOptions<ServiceAppConfiguration>
    {
    }
}

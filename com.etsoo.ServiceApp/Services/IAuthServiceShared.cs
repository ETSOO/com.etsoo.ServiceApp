using com.etsoo.CoreFramework.Services;
using com.etsoo.Utils.Actions;
using System.Net;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared authorization service interface
    /// 共享的授权服务接口
    /// </summary>
    public interface IAuthServiceShared : IServiceBase
    {
        /// <summary>
        /// Async exchange token
        /// 异步交换令牌
        /// </summary>
        /// <param name="tokenEncrypted">Token encrypted</param>
        /// <param name="device">Device identifier (readable name)</param>
        /// <param name="ip">IP</param>
        /// <param name="connectionId">Connection id</param>
        /// <returns>Result</returns>
        Task<IActionResult> ExchangeTokenAsync(string tokenEncrypted, string device, IPAddress ip, string? connectionId = null);
    }
}
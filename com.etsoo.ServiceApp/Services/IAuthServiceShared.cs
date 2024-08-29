using com.etsoo.ApiModel.Auth;
using com.etsoo.CoreFramework.Models;
using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.Utils.Actions;
using Microsoft.AspNetCore.Http;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared authorization service interface
    /// 共享的授权服务接口
    /// </summary>
    public interface IAuthServiceShared : IServiceBase, IAuthClient
    {
        /// <summary>
        /// Create access token from authorization code
        /// 从授权码创建访问令牌
        /// </summary>
        /// <param name="action">Request action</param>
        /// <param name="code">Authorization code</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Token data</returns>
        ValueTask<AppTokenData?> CreateTokenAsync(string action, string code, CancellationToken cancellationToken = default);

        /// <summary>
        /// Refresh the access token with refresh token
        /// 用刷新令牌获取访问令牌
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        Task<AppTokenData?> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

        /// <summary>
        /// Get user info
        /// 获取用户信息
        /// </summary>
        /// <param name="tokenData">Token data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        ValueTask<CurrentUser?> GetUserInfoAsync(AppTokenData tokenData, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validate auth callback
        /// 验证认证回调
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="stateCallback">Callback to verify request state</param>
        /// <param name="action">Request action</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Action result & Token data & actual state</returns>
        Task<(IActionResult result, AppTokenData? tokenData, string? state)> ValidateAuthAsync(HttpRequest request, Func<string, bool> stateCallback, string? action = null, CancellationToken cancellationToken = default);
    }
}
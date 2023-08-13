using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using com.etsoo.ServiceApp.Repo;
using com.etsoo.Utils.Actions;
using com.etsoo.Utils.Crypto;
using com.etsoo.WebUtils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared authorization service
    /// 共享的授权服务
    /// </summary>
    /// <typeparam name="A">Generic application</typeparam>
    public class AuthServiceShared<A> : ServiceShared<A, AuthRepoShared>, IAuthServiceShared where A : IServiceApp
    {
        readonly CoreFramework.Authentication.IAuthService _authService;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="logger">Logger</param>
        /// <param name="accessor">Http context accessor</param>
        public AuthServiceShared(A app, ILogger<AuthServiceShared<A>> logger, IHttpContextAccessor accessor)
            : base(app, new AuthRepoShared(app) { CancellationToken = accessor.CancellationToken() }, logger)
        {
            if (app.AuthService == null) throw new NullReferenceException(nameof(app.AuthService));
            _authService = app.AuthService;
        }

        /// <summary>
        /// Async exchange token
        /// 异步交换令牌
        /// </summary>
        /// <typeparam name="T">Generic user type</typeparam>
        /// <param name="tokenEncrypted">Token encrypted</param>
        /// <param name="device">Device identifier (readable name)</param>
        /// <param name="ip">IP</param>
        /// <param name="creator">User creator</param>
        /// <returns>Result</returns>
        public async Task<IActionResult> ExchangeTokenAsync<T>(string tokenEncrypted, string device, IPAddress ip, UserCreatorDelegate<T> creator) where T : IServiceUser
        {
            try
            {
                // Service passphrase
                var passphrase = App.Configuration.ServiceId.ToString();

                // Decrypt token
                var token = Decrypt(tokenEncrypted, passphrase, 120, true);
                if (string.IsNullOrEmpty(token))
                {
                    return ApplicationErrors.NoValidData.AsResult("Token");
                }

                // Validate the token from core system first
                var (claims, expired, _, _) = _authService.ValidateToken(token, $"Service{App.Configuration.ServiceId}");
                if (claims == null)
                {
                    return ApplicationErrors.NoValidData.AsResult("Claims");
                }

                var coreUser = CurrentUser.Create(claims);
                if (coreUser == null || expired)
                {
                    return ApplicationErrors.TokenExpired.AsResult();
                }

                // Organization and Uid are required
                if (coreUser.Organization == null || coreUser.Uid == null)
                {
                    return ApplicationErrors.NoValidData.AsResult("Organization");
                }

                if (ip == null || !ip.Equals(coreUser.ClientIp))
                {
                    return ApplicationErrors.IPAddressChanged.AsResult();
                }

                var result = await Repo.ExchangeTokenAsync(coreUser);

                if (result.Ok)
                {
                    // Copy data
                    result.Data["DeviceId"] = coreUser.DeviceId;
                    result.Data["Uid"] = coreUser.Uid;

                    // T.Create result is an interface, cannot cast back to T
                    var serviceUser = creator(result.Data, ip, coreUser.Language, coreUser.Region);
                    if (serviceUser == null)
                    {
                        Logger.LogDebug("Create user {type} failed with {result}", typeof(T), result.Data);
                        return ApplicationErrors.NoUserFound.AsResult();
                    }
                    result.Data[Constants.TokenName] = _authService.CreateAccessToken(serviceUser);

                    // Service passphase & device id
                    var servicePassphrase = CryptographyUtils.CreateRandString(RandStringKind.All, 32).ToString();
                    result.Data[Constants.ServiceDeviceName] = Encrypt(servicePassphrase, device, 1);
                    result.Data[Constants.ServicePassphrase] = EncryptWeb(servicePassphrase, passphrase);

                    // Expiry seconds
                    result.Data[Constants.SecondsName] = _authService.AccessTokenMinutes * 60;

                    // Remove user id / organization id to avoid information leaking
                    result.Data.Remove("Id");
                    result.Data.Remove("Organization");
                }

                return result;
            }
            catch (Exception ex)
            {
                // Return action result
                return LogException(ex);
            }
        }

        /// <summary>
        /// Async exchange token
        /// 异步交换令牌
        /// </summary>
        /// <param name="tokenEncrypted">Token encrypted</param>
        /// <param name="device">Device identifier (readable name)</param>
        /// <param name="ip">IP</param>
        /// <returns>Result</returns>
        public async Task<IActionResult> ExchangeTokenAsync(string tokenEncrypted, string device, IPAddress ip)
        {
            // ServiceUser not IServiceUser, otherwise is always null
            return await ExchangeTokenAsync(tokenEncrypted, device, ip, ServiceUser.CreateFromData);
        }
    }
}

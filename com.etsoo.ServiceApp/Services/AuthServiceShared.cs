using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using com.etsoo.ServiceApp.Application;
using com.etsoo.Utils.Actions;
using com.etsoo.Utils.Crypto;
using Microsoft.Extensions.Logging;
using System.Data.Common;
using System.Net;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared authorization service
    /// 共享的授权服务
    /// </summary>
    /// <typeparam name="A">Generic application</typeparam>
    public class AuthServiceShared<S, C, A, U> : ServiceBase<S, C, A, U>, IAuthServiceShared
        where S : ServiceAppConfiguration
        where C : DbConnection
        where A : IServiceBaseApp<S, C>
        where U : IServiceUser, IUserCreator<U>
    {
        readonly CoreFramework.Authentication.IAuthService _authService;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="logger">Logger</param>
        /// <param name="accessor">Http context accessor</param>
        public AuthServiceShared(A app, U? user, ILogger<AuthServiceShared<S, C, A, U>> logger)
            : base(app, user, "auth", logger, false)
        {
            if (app.AuthService == null) throw new NullReferenceException(nameof(app.AuthService));
            _authService = app.AuthService;
        }

        /// <summary>
        /// Async exchange token repository
        /// 异步交换令牌仓库
        /// </summary>
        /// <param name="coreUser">Core user token</param>
        /// <returns>Result</returns>
        protected virtual async ValueTask<IActionResult> ExchangeTokenRepoAsync(CurrentUser coreUser)
        {
            // Parameters
            var parameters = new DbParameters();
            parameters.Add("User", coreUser.IdInt);
            parameters.Add("UserUid", coreUser.Uid);
            parameters.Add("UserName", coreUser.Name);
            parameters.Add("Organization", coreUser.Organization);
            parameters.Add("OrganizationName", coreUser.OrganizationName);
            parameters.Add("RoleValue", coreUser.RoleValue);
            parameters.Add("Avatar", coreUser.Avatar);

            var command = CreateCommand(GetCommandName("exchange token"), parameters);
            return await QueryAsResultAsync(command);
        }

        /// <summary>
        /// Async exchange token
        /// 异步交换令牌
        /// </summary>
        /// <typeparam name="T">Generic user type</typeparam>
        /// <param name="tokenEncrypted">Token encrypted</param>
        /// <param name="device">Device identifier (readable name)</param>
        /// <param name="ip">IP</param>
        /// <param name="connectionId">Connection id</param>
        /// <returns>Result</returns>
        public async Task<IActionResult> ExchangeTokenAsync(string tokenEncrypted, string device, IPAddress ip, string? connectionId = null)
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

                var result = await ExchangeTokenRepoAsync(coreUser);

                if (result.Ok)
                {
                    // Copy data
                    result.Data["DeviceId"] = coreUser.DeviceId;

                    // Core system Uid = GUID
                    // Local system Uid = Global user id
                    // result.Data["Uid"] = coreUser.Uid;

                    // T.Create result is an interface, cannot cast back to T
                    var user = U.Create(result.Data, ip, coreUser.Language, coreUser.Region, connectionId);
                    if (user == null)
                    {
                        Logger.LogDebug("Create user {type} failed with {result}", typeof(C), result.Data);
                        return ApplicationErrors.NoUserFound.AsResult();
                    }
                    result.Data[Constants.TokenName] = _authService.CreateAccessToken(user);

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
    }
}

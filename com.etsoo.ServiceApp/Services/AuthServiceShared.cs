using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using com.etsoo.ServiceApp.Repo;
using com.etsoo.Utils.Actions;
using Microsoft.Extensions.Logging;
using System.Net;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Shared authorization service
    /// 共享的授权服务
    /// </summary>
    public class AuthServiceShared : ServiceShared<AuthRepoShared>
    {
        private const string TokenName = "Token";
        private const string ServiceDeviceName = "ServiceDeviceId";
        private const string SecondsName = "Seconds";

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="logger">Logger</param>
        public AuthServiceShared(IServiceApp app, ILogger logger)
            : base(app, new AuthRepoShared(app), logger)
        {
        }

        /// <summary>
        /// Async exchange token
        /// 异步交换令牌
        /// </summary>
        /// <param name="tokenEncrypted">Token encrypted</param>
        /// <param name="device">Device identifier</param>
        /// <param name="ip">IP</param>
        /// <returns>Result</returns>
        public async Task<IActionResult> ExchangeTokenAsync(string tokenEncrypted, string device, IPAddress ip)
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
                var (claims, expired, _, _) = App.AuthService.ValidateToken(token, $"Service{App.Configuration.ServiceId}");
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

                    var serviceUser = ServiceUser.Create(result.Data, ip, coreUser.Language, coreUser.Region);
                    if (serviceUser == null)
                    {
                        return ApplicationErrors.NoUserFound.AsResult();
                    }
                    result.Data[TokenName] = App.AuthService.CreateAccessToken(serviceUser);

                    // Service device id
                    var serviceDeviceId = await App.HashPasswordAsync(device);
                    result.Data[ServiceDeviceName] = Encrypt(serviceDeviceId, passphrase, 1);

                    // Expiry seconds
                    result.Data[SecondsName] = App.AuthService.AccessTokenMinutes * 60;

                    // Remove user id to avoid information leaking
                    result.Data.Remove("Id");
                    result.Data.Remove("OrganizationId");
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

using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Models;
using com.etsoo.ServiceApp.SmartERP;
using com.etsoo.Web;
using com.etsoo.WebUtils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Diagnostics.CodeAnalysis;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Map extensions
    /// 映射扩展
    /// </summary>
    public static class MapExtensions
    {
        /// <summary>
        /// Map authorization routes
        /// 映射授权路由
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        [RequiresUnreferencedCode("Required Unreferenced Code")]
        [RequiresDynamicCode("Require Dynamic Code")]
        public static RouteGroupBuilder MapAuth(this RouteGroupBuilder builder)
        {
            var g = builder.MapGroup("Auth").AllowAnonymous();

            g.MapPost("ExchangeLoginState", (ISEAuthService service, LoginStateRQ rq, CancellationToken cancellationToken)
                => service.ExchangeLoginStateAsync(rq, cancellationToken)
                ).WithDescription("Exchange login state / 交换登录状态");

            g.MapGet("GetLogInUrl", (ISEAuthService service, HttpContext context, string region, string? device)
                => service.GetLogInUrlResult(context.UserAgent(), region + device)
                ).WithDescription("Get log in URL / 获取登录地址");

            g.MapGet("LogIn", (ISEAuthService service, HttpContext context, CancellationToken cancellation)
                => service.AuthLogInAsync(context, cancellation)
                ).WithDescription("OAuth2 log in / OAuth2 登录");

            g.MapPut("ApiRefreshToken", (ISEAuthService service, ApiRefreshTokenRQ rq, CancellationToken cancellation)
                => service.ApiRefreshTokenAsync(rq, cancellation)
                ).WithDescription("API refresh token / 接口刷新令牌");

            g.MapPut("ExchangeToken", (ISEAuthService service, ApiTokenRQ rq, CancellationToken cancellation)
                => service.ExchangeTokenAsync(rq.Token, rq.TimeZone, cancellation)
                ).WithDescription("API exchange token with core system / 接口和核心系统交换令牌");

            g.MapPut("RefreshToken", (ISEAuthService service, IHttpContextAccessor accessor, RefreshTokenRQ rq, CancellationToken cancellationToken)
                => service.RefreshTokenAsync(accessor, rq, cancellationToken))
                .WithDescription("Refresh token / 刷新令牌");

            g.MapPut("Signout", async (ISEAuthService service, SignoutRQ rq, IHttpContextAccessor accessor, CancellationToken cancellationToken) =>
            {
                // Check device
                if (!service.CheckDevice(accessor.UserAgent(), rq.DeviceId, out var checkResult, out var cd))
                {
                    return checkResult;
                }

                var deviceCore = cd.Value.DeviceCore;

                var token = service.DecryptDeviceData(rq.Token, deviceCore);
                if (token == null)
                {
                    return ApplicationErrors.NoValidData.AsResult("Token");
                }

                return await service.SignoutAsync(token, cancellationToken);
            }).WithDescription("User signout / 用户退出");

            g.MapPut("SwitchOrg", (ISEAuthService service, IHttpContextAccessor accessor, SwitchOrgRQ rq, CancellationToken cancellationToken)
                => service.SwitchOrgAsync(accessor, rq, cancellationToken))
                .RequireAuthorization().WithDescription("Switch organization / 切换机构");

            return builder;
        }
    }
}
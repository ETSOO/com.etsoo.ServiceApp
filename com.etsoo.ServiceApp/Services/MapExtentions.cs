using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Models;
using com.etsoo.ServiceApp.SmartERP;
using com.etsoo.Web;
using com.etsoo.WebUtils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace com.etsoo.ServiceApp.Services
{
    /// <summary>
    /// Map extensions
    /// 映射扩展
    /// </summary>
    public static class MapExtensions
    {
        private static ISEAuthService GetService(this HttpContext context)
        {
            return context.GetService<ISEAuthService>();
        }

        /// <summary>
        /// Map authorization routes
        /// 映射授权路由
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static RouteGroupBuilder MapAuth(this RouteGroupBuilder builder)
        {
            var g = builder.MapGroup("Auth").AllowAnonymous();

            g.MapPost("ExchangeLoginState", async (context) =>
            {
                var service = context.GetService();
                var rq = await context.GetJsonAsync<LoginStateRQ>();
                var result = await service.ExchangeLoginStateAsync(rq, context.RequestAborted);
                await result.ExecuteAsync(context);
            }).WithDescription("Exchange login state / 交换登录状态");

            g.MapPost("GetAuthRequest", async (context) =>
            {
                var rq = await context.GetJsonAsync<GetAuthRequestRQ>();
                var result = context.GetService().GetAuthRequest(context.UserAgent, rq.Region + rq.Device, false);
                await result.ExecuteAsync(context);
            }).WithDescription("Get auth request / 获取授权请求");

            g.MapGet("GetLogInUrl", async (context) =>
            {
                var region = context.Request.Query["region"];
                var device = context.Request.Query["device"];
                var service = context.GetService();
                var result = service.GetLogInUrlResult(context.UserAgent, region + device);
                await result.ExecuteAsync(context);
            }).WithDescription("Get log in URL / 获取登录地址");

            g.MapGet("LogIn", async (context)
                => await context.GetService().AuthLogInAsync(context)
                ).WithDescription("OAuth2 log in / OAuth2 登录");

            g.MapPut("ApiRefreshToken", async (context) =>
            {
                var rq = await context.GetJsonAsync<ApiRefreshTokenRQ>();
                var data = await context.GetService().ApiRefreshTokenAsync(rq, context.RequestAborted);
                await context.WriteAsJsonAsync(data, ModelJsonSerializerContext.Default.ApiTokenData);
            }).WithDescription("API refresh token / 接口刷新令牌");

            g.MapPut("ExchangeToken", async (context) =>
            {
                var rq = await context.GetJsonAsync<ApiTokenRQ>();
                var service = context.GetService();
                var data = await service.ExchangeTokenAsync(rq.Token, rq.TimeZone, context.RequestAborted);
                await context.WriteAsJsonAsync(data, ModelJsonSerializerContext.Default.ApiTokenData);
            }).WithDescription("API exchange token with core system / 接口和核心系统交换令牌");

            g.MapPut("RefreshToken", async (context) =>
            {
                var rq = await context.GetJsonAsync<RefreshTokenRQ>();
                var service = context.GetService();
                var result = await service.RefreshTokenAsync(context, rq);
                await service.WriteUserResultAsync(context, result);
            }).WithDescription("Refresh token / 刷新令牌");

            g.MapPut("Signout", async (context) =>
            {
                var service = context.GetService();
                var rq = await context.GetJsonAsync<SignoutRQ>();

                // Check device
                if (!service.CheckDevice(context.UserAgent, rq.DeviceId, out var checkResult, out var cd))
                {
                    await checkResult.ExecuteAsync(context);
                    return;
                }

                var deviceCore = cd.Value.DeviceCore;

                var token = service.DecryptDeviceData(rq.Token, deviceCore);
                if (token == null)
                {
                    await ApplicationErrors.NoValidData.AsResult("Token").ExecuteAsync(context);
                    return;
                }

                var result = await service.SignoutAsync(token, context.RequestAborted);
                await result.ExecuteAsync(context);
            }).WithDescription("User signout / 用户退出");

            g.MapPut("SwitchOrg", async (context) =>
            {
                var service = context.GetService();
                var rq = await context.GetJsonAsync<SwitchOrgRQ>();
                var result = await service.SwitchOrgAsync(context, rq);
                await service.WriteUserResultAsync(context, result);
            }).RequireAuthorization().WithDescription("Switch organization / 切换机构");

            return builder;
        }
    }
}
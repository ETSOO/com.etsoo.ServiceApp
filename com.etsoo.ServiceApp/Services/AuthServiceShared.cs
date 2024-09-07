using com.etsoo.ApiModel.Auth;
using com.etsoo.CoreFramework.Models;
using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using com.etsoo.UserAgentParser;
using com.etsoo.Utils.Actions;
using com.etsoo.Utils.Crypto;
using com.etsoo.Utils.Serialization;
using com.etsoo.Utils.String;
using com.etsoo.Web;
using com.etsoo.WebUtils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Data.Common;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;

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
        where U : ICurrentUser, IUserCreator<U>
    {
        readonly CoreFramework.Authentication.IAuthService _authService;
        readonly IHttpClientFactory _clientFactory;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        /// <param name="logger">Logger</param>
        /// <param name="accessor">Http context accessor</param>
        public AuthServiceShared(A app, IUserAccessor<U> userAccessor, ILogger<AuthServiceShared<S, C, A, U>> logger, IHttpClientFactory clientFactory)
            : base(app, userAccessor.User, "auth", logger)
        {
            if (app.AuthService == null) throw new NullReferenceException(nameof(app.AuthService));
            _authService = app.AuthService;

            _clientFactory = clientFactory;
        }

        /// <summary>
        /// Get log in URL
        /// 获取登录URL
        /// </summary>
        /// <param name="state">Request state</param>
        /// <param name="loginHint">Login hint</param>
        /// <returns>URL</returns>
        public string GetLogInUrl(string state, string? loginHint = null)
        {
            return GetServerAuthUrl(AuthExtentions.LogInAction, state, App.Configuration.Scopes, false, loginHint);
        }

        /// <summary>
        /// Get sign up URL
        /// 获取注册URL
        /// </summary>
        /// <param name="state">Request state</param>
        /// <returns>URL</returns>
        public string GetSignUpUrl(string state)
        {
            return GetServerAuthUrl(AuthExtentions.SignUpAction, state, App.Configuration.Scopes);
        }

        /// <summary>
        /// Get server auth URL, for back-end processing
        /// 获取服务器授权URL，用于后端处理
        /// </summary>
        /// <param name="action">Action of the request</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="offline">Set to true if your application needs to refresh access tokens when the user is not present at the browser</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's identifier ID</param>
        /// <returns>URL</returns>
        public string GetServerAuthUrl(string action, string state, string scope, bool offline = false, string? loginHint = null)
        {
            var url = GetAuthUrl($"{App.Configuration.ServerRedirectUrl}/{action}", "code", scope, state, loginHint);
            if (offline)
            {
                url += "&access_type=offline";
            }
            return url;
        }

        /// <summary>
        /// Get script auth URL, for front-end page
        /// 获取脚本授权URL，用于前端页面
        /// </summary>
        /// <param name="action">Action of the request</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's identifier ID</param>
        /// <returns>URL</returns>
        public string GetScriptAuthUrl(string action, string state, string scope, string? loginHint = null)
        {
            return GetAuthUrl($"{App.Configuration.ScriptRedirectUrl}/{action}", "token", scope, state, loginHint);
        }

        /// <summary>
        /// Get auth URL
        /// 获取授权URL
        /// </summary>
        /// <param name="redirectUrl">The value must exactly match one of the authorized redirect URIs for the OAuth 2.0 client, which you configured in your client's API Console</param>
        /// <param name="responseType">Set the parameter value to 'code' for web server applications or 'token' for SPA</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's identifer ID</param>
        /// <returns>URL</returns>
        /// <exception cref="ArgumentNullException">Parameter 'redirectUrl' is required</exception>
        public string GetAuthUrl(string? redirectUrl, string responseType, string scope, string state, string? loginHint = null)
        {
            if (string.IsNullOrEmpty(redirectUrl))
            {
                throw new ArgumentNullException(nameof(redirectUrl));
            }

            var rq = new SortedDictionary<string, string>()
            {
                { "scope", scope },
                { "response_type", responseType },
                { "state", state },
                { "redirect_uri", redirectUrl },
                { "app_id", App.Configuration.AppId.ToString() },
                { "app_key", App.Configuration.AppKey }
            };

            if (!string.IsNullOrEmpty(loginHint))
            {
                rq.Add("login_hint", loginHint);
            }

            // With an extra '&' at the end
            var query = rq.JoinAsString().TrimEnd('&');

            // Siganature
            var sign = Convert.ToHexString(CryptographyUtils.HMACSHA256(query, App.Configuration.AppSecret));
            rq["sign"] = sign;

            // Request data to JSON
            var jsonRQ = JsonSerializer.Serialize(rq, CommonJsonSerializerContext.Default.DictionaryStringString);

            return $"{App.Configuration.Endpoint}?auth={HttpUtility.UrlEncode(jsonRQ)}";
        }

        /// <summary>
        /// Create access token from authorization code
        /// 从授权码创建访问令牌
        /// </summary>
        /// <param name="action">Request action</param>
        /// <param name="code">Authorization code</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Token data</returns>
        public async ValueTask<AppTokenData?> CreateTokenAsync(string action, string code, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(App.Configuration.ServerRedirectUrl))
            {
                throw new Exception("ServerRedirectUrl is required for server side authentication");
            }

            var rq = new SortedDictionary<string, string>
            {
                ["code"] = code,
                ["app_id"] = App.Configuration.AppId.ToString(),
                ["app_key"] = App.Configuration.AppKey,
                ["redirect_uri"] = $"{App.Configuration.ServerRedirectUrl}/{action}"
            };

            // With an extra '&' at the end
            var query = rq.JoinAsQuery().TrimEnd('&');

            // Siganature
            var sign = Convert.ToHexString(CryptographyUtils.HMACSHA256(query, App.Configuration.AppSecret));
            rq["sign"] = sign;

            var api = $"{App.Configuration.Endpoint}/api/Auth/OAuthCreateToken";
            var response = await _clientFactory.CreateClient().PostAsync(api, new FormUrlEncodedContent(rq), cancellationToken);

            response.EnsureSuccessStatusCode();

            return await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.AppTokenData, cancellationToken);
        }

        /// <summary>
        /// Refresh the access token with refresh token
        /// 用刷新令牌获取访问令牌
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<AppTokenData?> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var rq = new SortedDictionary<string, string>
            {
                ["app_id"] = App.Configuration.AppId.ToString(),
                ["app_key"] = App.Configuration.AppKey,
                ["refresh_token"] = refreshToken
            };

            // With an extra '&' at the end
            var query = rq.JoinAsQuery().TrimEnd('&');

            // Siganature
            var sign = Convert.ToHexString(CryptographyUtils.HMACSHA256(query, App.Configuration.AppSecret));
            rq["sign"] = sign;

            var api = $"{App.Configuration.Endpoint}/api/Auth/OAuthRefreshToken";
            var response = await _clientFactory.CreateClient().PostAsync(api, new FormUrlEncodedContent(rq), cancellationToken);

            response.EnsureSuccessStatusCode();

            return await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.AppTokenData, cancellationToken);
        }

        /// <summary>
        /// Get user info
        /// 获取用户信息
        /// </summary>
        /// <param name="tokenData">Token data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async ValueTask<CurrentUser?> GetUserInfoAsync(AppTokenData tokenData, CancellationToken cancellationToken = default)
        {
            if (!string.IsNullOrEmpty(tokenData.IdToken))
            {
                var (cp, _) = _authService.ValidateIdToken(tokenData.IdToken, App.Configuration.AppSecret);
                var user = CurrentUser.Create(cp);
                return user;
            }

            var client = _clientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenData.AccessToken);

            var api = $"{App.Configuration.Endpoint}/api/Auth/OAuthUserInfo";

            var response = await client.GetAsync(api, cancellationToken);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.CurrentUser, cancellationToken);
        }

        /// <summary>
        /// Get user info from callback request
        /// 从回调请求获取用户信息
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="state">Request state</param>
        /// <param name="action">Request action</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Action result & user information & actual state</returns>
        public ValueTask<(IActionResult result, AuthUserInfo? userInfo, string? state)> GetUserInfoAsync(HttpRequest request, string state, string? action = null, CancellationToken cancellationToken = default)
        {
            return GetUserInfoAsync(request, s => s == state, action, cancellationToken);
        }

        /// <summary>
        /// Get user info from callback request
        /// 从回调请求获取用户信息
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="stateCallback">Callback to verify request state</param>
        /// <param name="action">Request action</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Action result & user information & actual state</returns>
        public async ValueTask<(IActionResult result, AuthUserInfo? userInfo, string? state)> GetUserInfoAsync(HttpRequest request, Func<string, bool> stateCallback, string? action = null, CancellationToken cancellationToken = default)
        {
            var (result, tokenData, state) = await ValidateAuthAsync(request, stateCallback, action, cancellationToken);
            AuthUserInfo? userInfo = null;
            if (result.Ok && tokenData != null)
            {
                var data = await GetUserInfoAsync(tokenData, cancellationToken);
                if (data == null)
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "userinfo"
                    };
                }
                else
                {
                    userInfo = new AuthUserInfo
                    {
                        OpenId = data.Uid ?? data.Id.ToString(),
                        Name = data.Name,
                        Picture = data.Avatar
                    };
                }
            }

            return (result, userInfo, state);
        }

        /// <summary>
        /// Validate auth callback
        /// 验证认证回调
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="stateCallback">Callback to verify request state</param>
        /// <param name="action">Request action</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Action result & Token data & actual state</returns>
        public async Task<(IActionResult result, AppTokenData? tokenData, string? state)> ValidateAuthAsync(HttpRequest request, Func<string, bool> stateCallback, string? action = null, CancellationToken cancellationToken = default)
        {
            IActionResult result;
            AppTokenData? tokenData = null;
            string? state = null;

            if (request.Query.TryGetValue("error", out var error))
            {
                var field = request.Query["error_field"].ToString();

                result = new ActionResult
                {
                    Type = "AccessDenied",
                    Field = field,
                    Title = error
                };
            }
            else if (request.Query.TryGetValue("state", out var actualState) && request.Query.TryGetValue("code", out var codeSource))
            {
                state = actualState.ToString();
                var code = codeSource.ToString();
                if (!stateCallback(state))
                {
                    result = new ActionResult
                    {
                        Type = "AccessDenied",
                        Field = "state"
                    };
                }
                else if (string.IsNullOrEmpty(code))
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "code"
                    };
                }
                else
                {
                    try
                    {
                        action ??= request.GetRequestAction();
                        tokenData = await CreateTokenAsync(action, code, cancellationToken);
                        if (tokenData == null)
                        {
                            result = new ActionResult
                            {
                                Type = "NoDataReturned",
                                Field = "token"
                            };
                        }
                        else
                        {
                            result = ActionResult.Success;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(ex, "Create token failed");
                        result = ActionResult.From(ex);
                    }
                }
            }
            else
            {
                result = new ActionResult
                {
                    Type = "NoDataReturned",
                    Field = "state"
                };
            }

            return (result, tokenData, state);
        }

        /// <summary>
        /// Get log in URL result
        /// 获取登录URL结果
        /// </summary>
        /// <param name="client">Auth client</param>
        /// <param name="userAgent">User agent</param>
        /// <param name="deviceId">Region (like CN) & Device id</param>
        /// <returns>Result</returns>
        public IResult GetLogInUrlResult(string? userAgent, string deviceId)
        {
            if (!this.CheckDevice(userAgent, deviceId[2..], out var result, out _))
            {
                return Results.BadRequest(result);
            }
            else
            {
                var url = GetServerAuthUrl(AuthExtentions.LogInAction, deviceId, App.Configuration.Scopes, true);
                return Results.Content(url, "text/plain");
            }
        }

        /// <summary>
        /// Log in from OAuth2 client
        /// 从OAuth2客户端登录
        /// </summary>
        /// <param name="context">OAuth2 Request HTTPContext</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Action result & current user & Token data & login data</returns>
        public async ValueTask<(IActionResult result, CurrentUser? user, AppTokenData? tokenData, AuthLoginValidateData? data)> LogInAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            (string DeviceCore, UAParser Parser)? parser = null;
            string? region = null;
            string? deviceId = null;
            CurrentUser? user = null;

            var (result, tokenData, state) = await ValidateAuthAsync(context.Request, (s) =>
            {
                // We put the region code like 'CN' at the beginning of the device id
                region = s[..2];

                // The device id is the rest of the string
                deviceId = s[2..];

                return this.CheckDevice(context.UserAgent(), deviceId.Replace(" ", "+"), out _, out parser);
            }, AuthExtentions.LogInAction, cancellationToken);

            if (result.Ok && tokenData != null)
            {
                user = await GetUserInfoAsync(tokenData, cancellationToken);
                if (user == null)
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "userinfo"
                    };
                }
            }

            AuthLoginValidateData? data = null;
            if (parser != null && region != null && deviceId != null)
            {
                data = new AuthLoginValidateData
                {
                    DeviceId = deviceId,
                    Region = region,
                    Parser = parser.Value.Parser
                };
            }

            return (result, user, tokenData, data);
        }

        /// <summary>
        /// Log in from OAuth2 client and authorized
        /// 从OAuth2客户端登录并授权
        /// </summary>
        /// <param name="context">OAuth2 Request HTTPContext</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Action result & current user & login data</returns>
        public async ValueTask AuthLogInAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            var (result, user, tokenData, _) = await LogInAsync(context, cancellationToken);

            if (result.Ok)
            {
                if (user == null || tokenData == null)
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "user"
                    };
                }
                else if (tokenData.RefreshToken == null)
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "refreshtoken"
                    };
                }
                else
                {
                    // Redirect to the success URL
                    var successUrl = App.Configuration.AuthSuccessUrl;
                    context.Response.Redirect($"{successUrl}", true);
                    return;
                }
            }

            // Redirect to the failure URL
            var url = App.Configuration.AuthFailureUrl;
            var jsonResult = JsonSerializer.Serialize(result, CommonJsonSerializerContext.Default.ActionResult);
            context.Response.Redirect($"{url}?error={HttpUtility.UrlEncode(jsonResult)}", true);
        }
    }
}

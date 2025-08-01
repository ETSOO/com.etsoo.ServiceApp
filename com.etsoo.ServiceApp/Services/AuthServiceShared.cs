﻿using com.etsoo.ApiModel.Auth;
using com.etsoo.CoreFramework.Application;
using com.etsoo.CoreFramework.Models;
using com.etsoo.CoreFramework.Services;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.Application;
using com.etsoo.UserAgentParser;
using com.etsoo.Utils;
using com.etsoo.Utils.Actions;
using com.etsoo.Utils.Crypto;
using com.etsoo.Utils.Serialization;
using com.etsoo.Web;
using com.etsoo.WebUtils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Data.Common;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
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
        const string BearerTokenType = "Bearer";

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
            return GetServerAuthUrl(action, state, false, scope, offline, loginHint);
        }

        /// <summary>
        /// Get server auth URL, for back-end processing
        /// 获取服务器授权URL，用于后端处理
        /// </summary>
        /// <param name="action">Action of the request</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="tokenResponse">Is 'token' response, 'false' means 'code'</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="offline">Set to true if your application needs to refresh access tokens when the user is not present at the browser</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's identifier ID</param>
        /// <returns>URL</returns>
        public string GetServerAuthUrl(string action, string state, bool tokenResponse, string scope, bool offline = false, string? loginHint = null)
        {
            var responseType = tokenResponse ? AuthRequest.TokenResponseType : AuthRequest.CodeResponseType;
            return GetAuthUrl($"{App.Configuration.ServerRedirectUrl}/{action}", responseType, scope, state, loginHint, offline ? AuthRequest.OfflineAccessType : null);
        }

        /// <summary>
        /// Get server auth request, for back-end processing
        /// 获取服务器授权请求，用于后端处理
        /// </summary>
        /// <param name="action">Action of the request</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="tokenResponse">Is 'token' response, 'false' means 'code'</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="offline">Set to true if your application needs to refresh access tokens when the user is not present at the browser</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's identifier ID</param>
        /// <returns>AuthRequest</returns>
        public AuthRequest GetServerAuthRequest(string action, string state, bool tokenResponse, string scope, bool offline = false, string? loginHint = null)
        {
            var responseType = tokenResponse ? AuthRequest.TokenResponseType : AuthRequest.CodeResponseType;
            return GetAuthRequest($"{App.Configuration.ServerRedirectUrl}/{action}", responseType, scope, state, loginHint, offline ? AuthRequest.OfflineAccessType : null);
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
            return GetAuthUrl($"{App.Configuration.ScriptRedirectUrl}/{action}", AuthRequest.TokenResponseType, scope, state, loginHint, AuthRequest.OfflineAccessType);
        }

        /// <summary>
        /// Get auth request
        /// 获取授权请求
        /// </summary>
        /// <param name="redirectUrl">The value must exactly match one of the authorized redirect URIs for the OAuth 2.0 client, which you configured in your client's API Console</param>
        /// <param name="responseType">Set the parameter value to 'code' for web server applications or 'token' for SPA</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's identifer ID</param>
        /// <param name="accessType">Access type, set to 'offline' will return the refresh token</param>
        /// <returns>AuthRequest</returns>
        /// <exception cref="ArgumentNullException">Parameter 'redirectUrl' is required</exception>
        public AuthRequest GetAuthRequest(string? redirectUrl, string responseType, string scope, string state, string? loginHint = null, string? accessType = null)
        {
            if (string.IsNullOrEmpty(redirectUrl) || !Uri.TryCreate(redirectUrl, UriKind.Absolute, out var uri))
            {
                throw new ArgumentNullException(nameof(redirectUrl));
            }

            // Encrypt the state
            // 加密状态
            var encryptedState = CryptographyUtils.AESEncrypt(state, App.Configuration.AppSecret);

            var rq = new AuthRequest
            {
                AccessType = accessType,
                AppId = App.Configuration.AppId,
                AppKey = App.Configuration.AppKey,
                LoginHint = loginHint,
                RedirectUri = uri,
                ResponseType = responseType,
                Scope = scope,
                State = encryptedState
            };

            // Siganature
            rq.Sign = rq.SignWith(App.Configuration.AppSecret);

            // Return
            return rq;
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
        /// <param name="accessType">Access type, set to 'offline' will return the refresh token</param>
        /// <returns>URL</returns>
        /// <exception cref="ArgumentNullException">Parameter 'redirectUrl' is required</exception>
        public string GetAuthUrl(string? redirectUrl, string responseType, string scope, string state, string? loginHint = null, string? accessType = null)
        {
            // Request
            var rq = GetAuthRequest(redirectUrl, responseType, scope, state, loginHint, accessType);

            // Request data to JSON
            var jsonRQ = JsonSerializer.Serialize(rq, ModelJsonSerializerContext.Default.AuthRequest);

            return $"{App.Configuration.WebUrl}?auth={HttpUtility.UrlEncode(jsonRQ)}";
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

            var rq = new AuthCreateTokenRQ
            {
                AppId = App.Configuration.AppId,
                AppKey = App.Configuration.AppKey,
                Code = code,
                RedirectUri = new Uri($"{App.Configuration.ServerRedirectUrl}/{action}", UriKind.Absolute)
            };

            // Siganature
            rq.Sign = rq.SignWith(App.Configuration.AppSecret);

            var vr = rq.Validate();
            if (vr != null && !vr.Ok)
            {
                Logger.LogError("CreateTokenAsync failed with validation: {result}", vr);
                return null;
            }

            var api = $"{App.Configuration.ApiUrl}/Auth/OAuthCreateToken";
            var client = _clientFactory.CreateClient();

            using var response = await client.PostAsJsonAsync(api, rq, ModelJsonSerializerContext.Default.AuthCreateTokenRQ, cancellationToken);

            try
            {
                response.EnsureSuccessStatusCode();
            }
            catch
            {
                // Log the response content
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                Logger.LogError("CreateTokenAsync failed with response: {content}", content);

                throw;
            }

            return await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.AppTokenData, cancellationToken);
        }

        /// <summary>
        /// Refresh token, only for the service application
        /// 刷新令牌，仅用于服务应用
        /// </summary>
        /// <param name="accessor">HTTP accessor</param>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async ValueTask<IActionResult> RefreshTokenAsync(IHttpContextAccessor accessor, RefreshTokenRQ rq, CancellationToken cancellationToken)
        {
            // Token
            string? token;
            if (accessor.HttpContext?.Request.Headers.TryGetValue(Constants.RefreshTokenHeaderName, out var value) is true)
            {
                token = value.ToString();
            }
            else
            {
                return ApplicationErrors.NoValidData.AsResult("Token");
            }

            if (string.IsNullOrEmpty(token))
            {
                return ApplicationErrors.NoValidData.AsResult("Token");
            }

            var data = new RefreshTokenData
            {
                DeviceId = rq.DeviceId,
                UserAgent = accessor.UserAgent(),
                Token = token,
                TimeZone = rq.TimeZone
            };

            var (result, newRefeshToken) = await RefreshTokenAsync(data, cancellationToken);

            if (result.Ok && newRefeshToken != null)
            {
                MinimalApiUtils.OutputRefreshToken(accessor, newRefeshToken);
            }

            return result;
        }

        /// <summary>
        /// Refresh the token
        /// 刷新访问令牌
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <param name="timeZone">Time zone</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<AppTokenData?> RefreshTokenAsync(string refreshToken, string timeZone, CancellationToken cancellationToken = default)
        {
            var rq = new AuthRefreshTokenRQ
            {
                AppId = App.Configuration.AppId,
                AppKey = App.Configuration.AppKey,
                RefreshToken = refreshToken,
                TimeZone = timeZone
            };

            // Siganature
            rq.Sign = rq.SignWith(App.Configuration.AppSecret);

            try
            {
                var api = $"{App.Configuration.ApiUrl}/Auth/OAuthRefreshToken";

                using var response = await _clientFactory.CreateClient().PostAsJsonAsync(api, rq, ModelJsonSerializerContext.Default.AuthRefreshTokenRQ, cancellationToken);

                try
                {
                    response.EnsureSuccessStatusCode();
                }
                catch
                {
                    // Log the response content
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    Logger.LogError("RefreshTokenAsync failed with response: {content}", content);

                    throw;
                }

                return await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.AppTokenData, cancellationToken);
            }
            catch (Exception ex)
            {
                LogException(ex);
                return null;
            }
        }

        /// <summary>
        /// Refresh the token with result
        /// 刷新访问令牌为结果
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <param name="timeZone">Time zone</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result & new refresh token</returns>
        public async Task<(IActionResult result, string? newRefreshToken)> RefreshTokenResultAsync(string refreshToken, string timeZone, CancellationToken cancellationToken = default)
        {
            var rq = new AuthRefreshTokenRQ
            {
                AppId = App.Configuration.AppId,
                AppKey = App.Configuration.AppKey,
                RefreshToken = refreshToken,
                TimeZone = timeZone
            };

            // Siganature
            rq.Sign = rq.SignWith(App.Configuration.AppSecret);

            try
            {
                var api = $"{App.Configuration.ApiUrl}/Auth/OAuthRefreshTokenResult";

                using var response = await _clientFactory.CreateClient().PostAsJsonAsync(api, rq, ModelJsonSerializerContext.Default.AuthRefreshTokenRQ, cancellationToken);

                try
                {
                    response.EnsureSuccessStatusCode();
                }
                catch
                {
                    // Log the response content
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    Logger.LogError("RefreshTokenResultAsync failed with response: {content}", content);

                    throw;
                }

                // Get the refresh token header
                var newRefreshToken = response.Headers.GetValues(Constants.RefreshTokenHeaderName).FirstOrDefault();

                if (string.IsNullOrEmpty(newRefreshToken))
                {
                    return (ApplicationErrors.NoDataReturned.AsResult("RefreshToken"), null);
                }

                var result = await response.Content.ReadFromJsonAsync(CommonJsonSerializerContext.Default.IActionResult, cancellationToken);
                if (result == null)
                {
                    return (ApplicationErrors.NoDataReturned.AsResult("Result"), null);
                }

                return (result, newRefreshToken);
            }
            catch (Exception ex)
            {
                var result = LogException(ex);
                return (result, null);
            }
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
                var user = CurrentUser.Create(cp, out var reason);

                if (user == null)
                {
                    Logger.LogError("Failed to create user: {reason}", reason);
                }

                return user;
            }

            var client = _clientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(tokenData.TokenType, tokenData.AccessToken);

            try
            {
                var api = $"{App.Configuration.ApiUrl}/Auth/OAuthUserInfo";

                using var response = await client.GetAsync(api, cancellationToken);

                try
                {
                    response.EnsureSuccessStatusCode();
                }
                catch
                {
                    // Log the response content
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    Logger.LogError("GetUserInfoAsync failed with response: {content}", content);

                    throw;
                }

                return await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.CurrentUser, cancellationToken);
            }
            catch (Exception ex)
            {
                LogException(ex);
                return null;
            }
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
            else if (request.Query.TryGetValue("state", out var actualState))
            {
                state = actualState.ToString();
                if (!stateCallback(state))
                {
                    result = new ActionResult
                    {
                        Type = "AccessDenied",
                        Field = "state"
                    };
                }
                else if (request.Query.TryGetValue(AuthRequest.TokenResponseType, out var tokenSource))
                {
                    // Token
                    try
                    {
                        tokenData = JsonSerializer.Deserialize(tokenSource.ToString(), ModelJsonSerializerContext.Default.AppTokenData);
                        if (tokenData == null)
                        {
                            result = new ActionResult
                            {
                                Type = "NoDataReturned",
                                Field = "post_token"
                            };
                        }
                        else
                        {
                            result = ActionResult.Success;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(ex, "Post token failed");
                        result = ActionResult.From(ex);
                    }
                }
                else if (request.Query.TryGetValue(AuthRequest.CodeResponseType, out var codeSource))
                {
                    // Code
                    var code = codeSource.ToString();
                    if (string.IsNullOrEmpty(code))
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
                        Field = "code"
                    };
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
        /// Get log in auth request
        /// 获取登录授权请求
        /// </summary>
        /// <param name="userAgent">User agent</param>
        /// <param name="deviceId">Region (like CN) & Device id</param>
        /// <param name="isUrl">Is URL format or not</param>
        /// <returns>AuthRequest</returns>
        public IResult GetAuthRequest(string? userAgent, string deviceId, bool isUrl = false)
        {
            if (string.IsNullOrEmpty(userAgent))
            {
                return Results.BadRequest();
            }

            var region = deviceId[..2];
            if (deviceId.Length < 10)
            {
                var parser = new UAParser(userAgent);
                if (!parser.Valid || parser.IsBot)
                {
                    return Results.BadRequest();
                }

                deviceId = CreateLoginState(parser.ToShortName(), region);
            }
            else if (!this.CheckDevice(userAgent, deviceId[2..], out var result, out var d))
            {
                return Results.BadRequest(result);
            }
            else
            {
                deviceId = CreateLoginState(d.Value.Parser.ToShortName(), region);
            }

            if (isUrl)
            {
                var url = GetServerAuthUrl(AuthExtentions.LogInAction, deviceId, true, App.Configuration.Scopes, true);
                return Results.Content(url, "text/plain");
            }
            else
            {
                var rq = GetServerAuthRequest(AuthExtentions.LogInAction, deviceId, true, App.Configuration.Scopes, true);
                return Results.Json(rq, ModelJsonSerializerContext.Default.AuthRequest);
            }
        }

        /// <summary>
        /// Get log in URL result
        /// 获取登录URL结果
        /// </summary>
        /// <param name="userAgent">User agent</param>
        /// <param name="deviceId">Region (like CN) & Device id</param>
        /// <returns>Result</returns>
        public IResult GetLogInUrlResult(string? userAgent, string deviceId)
        {
            return GetAuthRequest(userAgent, deviceId, true);
        }

        private string CreateLoginState(string device, string region)
        {
            return region + App.HashPassword(App.Configuration.AppId + device);
        }

        /// <summary>
        /// Exchange login state
        /// 交换登录状态
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async ValueTask<IActionResult> ExchangeLoginStateAsync(LoginStateRQ rq, CancellationToken cancellationToken = default)
        {
            // Check signature
            var expectedSignature = rq.SignWith(App.Configuration.AppSecret);
            if (!rq.Sign.Equals(expectedSignature))
            {
                return ApplicationErrors.NoValidData.AsResult(nameof(rq.Sign));
            }

            if (rq.TotalMinutes() > 2)
            {
                return ApplicationErrors.SignExpired.AsResult();
            }

            await Task.CompletedTask;

            var state = CreateLoginState(rq.Device, rq.Region);
            var encryptedState = CryptographyUtils.AESEncrypt(rq.Timestamp + state, App.Configuration.AppSecret);

            return ActionResult.Succeed(encryptedState);
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
            var parser = new UAParser(context.UserAgent());
            string? region = null;
            string? deviceId = null;
            CurrentUser? user = null;

            var (result, tokenData, state) = await ValidateAuthAsync(context.Request, (es) =>
            {
                // Decrypt the state
                var bytes = CryptographyUtils.AESDecrypt(es, App.Configuration.AppSecret);
                if (bytes == null || bytes.Length == 0)
                {
                    return false;
                }

                // Source state
                var s = Encoding.UTF8.GetString(bytes);

                // We put the region code like 'CN' at the beginning of the device id
                region = s[..2];

                if (s.Equals(CreateLoginState(parser.ToShortName(), region)))
                {
                    // The device id is the rest of the string
                    deviceId = s[2..];

                    return true;
                }
                else
                {
                    return false;
                }
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
            if (region != null && deviceId != null)
            {
                data = new AuthLoginValidateData
                {
                    DeviceId = deviceId,
                    Region = region,
                    Parser = parser
                };
            }

            return (result, user, tokenData, data);
        }

        /// <summary>
        /// Serialize user data
        /// 序列号用户数据
        /// </summary>
        /// <param name="result">Action result</param>
        /// <returns>Result</returns>
        protected virtual string SerializeUser(ActionResult result)
        {
            return JsonSerializer.Serialize(result, CommonJsonSerializerContext.Default.ActionResult);
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
            if (MinimalApiUtils.CheckDevice(context.UserAgent(), out var result, out var parser))
            {
                try
                {
                    var (loginResult, user, tokenData, _) = await LogInAsync(context, cancellationToken);

                    if (loginResult.Ok)
                    {
                        if (user == null || tokenData == null)
                        {
                            result = new ActionResult
                            {
                                Type = "NoDataReturned",
                                Field = "user"
                            };
                        }
                        else
                        {
                            // Create the results
                            var (service, core, serviceRefreshToken) = await EnrichUserResultsAsync(user, tokenData, cancellationToken);

                            if (service.Ok)
                            {
                                // Return the refresh token
                                service.Data[ServiceConstants.RefreshTokenName] = serviceRefreshToken;

                                // Service passphrase
                                // Passphrase is encrypted by front-end information for random string while the device id is encrypted by the parser data
                                var randomChars = CryptographyUtils.CreateRandString(RandStringKind.All, 32).ToString();
                                var passphraseKey = $"{user.Uid}-{App.Configuration.AppId}";
                                var passphrase = EncryptWeb(randomChars, passphraseKey);
                                var deviceId = Encrypt(randomChars, parser.ToShortName());
                                service.Data["Passphrase"] = passphrase;
                                service.Data["ClientDeviceId"] = deviceId;

                                var serviceJson = SerializeUser(service);
                                var coreJson = core == null ? string.Empty : JsonSerializer.Serialize(core, ModelJsonSerializerContext.Default.ApiTokenData);

                                // Redirect to the success URL
                                var successUrl = App.Configuration.AuthSuccessUrl;
                                context.Response.Redirect($"{successUrl}?culture={user.Language.Name}&result={HttpUtility.UrlEncode(serviceJson)}&core={HttpUtility.UrlEncode(coreJson)}", true);
                                return;
                            }
                            else
                            {
                                result = service;
                            }
                        }
                    }
                    else
                    {
                        result = loginResult;
                    }
                }
                catch (Exception ex)
                {
                    result = LogException(ex);
                }
            }

            // Redirect to the failure URL
            var url = App.Configuration.AuthFailureUrl;
            var jsonResult = JsonSerializer.Serialize(result, CommonJsonSerializerContext.Default.ActionResult);
            context.Response.Redirect($"{url}?error={HttpUtility.UrlEncode(jsonResult)}", true);
        }

        /// <summary>
        /// Refresh token, only for the service application
        /// 刷新令牌，仅用于服务应用
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public virtual async ValueTask<(IActionResult result, string? newRefreshToken)> RefreshTokenAsync(RefreshTokenData data, CancellationToken cancellationToken = default)
        {
            // Check device
            if (!this.CheckDevice(data.UserAgent, data.DeviceId, out var checkResult, out var cd))
            {
                return (checkResult, null);
            }

            var deviceCore = cd.Value.DeviceCore;

            var token = DecryptDeviceData(data.Token, deviceCore);

            if (string.IsNullOrEmpty(token))
            {
                return (ApplicationErrors.NoValidData.AsResult("Token"), null);
            }

            var rq = new ApiRefreshTokenRQ
            {
                Token = token,
                AppId = App.Configuration.AppId,
                TimeZone = data.TimeZone
            };

            var (result, pd, refreshToken, user) = await EnrichRefreshTokenAsync(rq, cancellationToken);
            if (result.Ok && pd != null && user != null)
            {
                await EnrichUserResultAsync(result, user, cancellationToken);
                if (!result.Ok)
                {
                    return (result, null);
                }

                pd.SaveTo(result);
            }

            return (result, refreshToken);
        }

        /// <summary>
        /// Enrich refresh token for service application, default implementation is to refresh the token from the core system
        /// 为服务应用增强刷新令牌，默认实现是从核心系统刷新令牌
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result & public data & new refresh token</returns>
        protected virtual async ValueTask<(IActionResult result, PublicServiceUserData? data, string? newRefreshToken, CurrentUser? user)> EnrichRefreshTokenAsync(ApiRefreshTokenRQ rq, CancellationToken cancellationToken)
        {
            var vr = rq.Validate();
            if (vr != null && !vr.Ok)
            {
                return (vr, null, null, null);
            }

            var tokenData = await RefreshTokenAsync(rq.Token, rq.TimeZone, cancellationToken);
            if (tokenData == null)
            {
                return (ApplicationErrors.TokenExpired.AsResult(), null, null, null);
            }

            var user = await GetUserInfoAsync(tokenData, cancellationToken);
            if (user == null)
            {
                return (ApplicationErrors.NoDataReturned.AsResult("User"), null, null, null);
            }

            if (user.Scopes?.Contains(CurrentUser.AppIdToScope(rq.AppId)) is not true)
            {
                return (ApplicationErrors.AccessDenied.AsResult("Scope"), null, null, null);
            }

            var refreshToken = tokenData.RefreshToken;
            if (string.IsNullOrEmpty(refreshToken))
            {
                return (ApplicationErrors.NoDataReturned.AsResult("RefreshToken"), null, null, null);
            }

            var (data, _, newRefreshToken) = await EnrichUserAsync(user, cancellationToken);

            return (ActionResult.Success, data, newRefreshToken ?? refreshToken, user);
        }

        /// <summary>
        /// Enrich user data for service application, default implementation is to use the core system user
        /// 为服务应用增强用户数据，默认实现是使用核心系统用户
        /// </summary>
        /// <param name="user">Core system user</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Public data, enriched user, and new refresh token</returns>
        protected virtual async ValueTask<(PublicServiceUserData data, IMinUserToken user, string? newRefreshToken)> EnrichUserAsync(ICurrentUser user, CancellationToken cancellationToken)
        {
            var accessToken = _authService.CreateAccessToken(user);

            var data = new PublicServiceUserData
            {
                Name = user.Name,
                GivenName = user.GivenName,
                FamilyName = user.FamilyName,
                LatinGivenName = user.LatinGivenName,
                LatinFamilyName = user.LatinFamilyName,
                Avatar = user.Avatar,
                Organization = user.OrganizationInt > 0 ? user.OrganizationInt : null,
                IsChannel = !string.IsNullOrEmpty(user.ChannelOrganization),
                IsParent = !string.IsNullOrEmpty(user.ParentOrganization),
                Role = user.RoleValue,
                TokenScheme = "Bearer",
                Token = accessToken,
                Seconds = _authService.AccessTokenMinutes * 60,
                Uid = user.Uid,
                OrganizationName = user.OrganizationName
            };

            await Task.CompletedTask;

            return (data, user, null);
        }

        /// <summary>
        /// Enrich user result
        /// 增强用户结果
        /// </summary>
        /// <param name="result">Action result</param>
        /// <param name="user">Current user</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task</returns>
        protected virtual Task EnrichUserResultAsync(IActionResult result, ICurrentUser user, CancellationToken cancellationToken)
        {
            // Change the result's failure state to stop the next process
            return Task.CompletedTask;
        }

        /// <summary>
        /// Enrich user results
        /// 增强用户结果
        /// </summary>
        /// <param name="user">User</param>
        /// <param name="tokenData">Token data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        private async Task<(ActionResult service, ApiTokenData? core, string? serviceRefreshToken)> EnrichUserResultsAsync(ICurrentUser user, AppTokenData tokenData, CancellationToken cancellationToken)
        {
            if (tokenData.RefreshToken == null)
            {
                return (new ActionResult
                {
                    Type = "NoDataReturned",
                    Field = "refreshtoken"
                }, null, null);
            }

            var serviceResult = ActionResult.Success;

            await EnrichUserResultAsync(serviceResult, user, cancellationToken);

            if (!serviceResult.Ok)
            {
                return (serviceResult, null, null);
            }

            var (data, _, serviceRefreshToken) = await EnrichUserAsync(user, cancellationToken);

            if (string.IsNullOrEmpty(serviceRefreshToken))
            {
                // Share the same data, no necessary to return duplicate data
                serviceRefreshToken = tokenData.RefreshToken;
            }

            data.SaveTo(serviceResult);

            var core = new ApiTokenData
            {
                AccessToken = tokenData.AccessToken,
                ExpiresIn = tokenData.ExpiresIn,
                TokenType = tokenData.TokenType,
                RefreshToken = tokenData.RefreshToken
            };

            return (serviceResult, core, serviceRefreshToken);
        }

        /// <summary>
        /// Refresh API token
        /// 刷新API令牌
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async ValueTask<ApiTokenData?> ApiRefreshTokenAsync(ApiRefreshTokenRQ rq, CancellationToken cancellationToken = default)
        {
            var (result, pd, refreshToken, _) = await EnrichRefreshTokenAsync(rq, cancellationToken);
            if (result.Ok && pd != null && !string.IsNullOrEmpty(refreshToken))
            {
                return new ApiTokenData
                {
                    AccessToken = pd.Token,
                    ExpiresIn = pd.Seconds,
                    TokenType = pd.TokenScheme,
                    RefreshToken = refreshToken
                };
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Exchange API token from core system
        /// 从核心系统交换API令牌
        /// </summary>
        /// <param name="token">Refresh token</param>
        /// <param name="timeZone">Time zone</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async ValueTask<ApiTokenData?> ExchangeTokenAsync(string token, string timeZone, CancellationToken cancellationToken = default)
        {
            // Core system refresh token
            var tokenData = await RefreshTokenAsync(token, timeZone, cancellationToken);
            if (tokenData == null || tokenData.RefreshToken == null)
            {
                return null;
            }

            return new ApiTokenData
            {
                AccessToken = tokenData.AccessToken,
                ExpiresIn = tokenData.ExpiresIn,
                TokenType = tokenData.TokenType,
                RefreshToken = tokenData.RefreshToken
            };
        }

        /// <summary>
        /// Sign out
        /// 退出
        /// </summary>
        /// <param name="token">Refresh token</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task</returns>
        public virtual async ValueTask<IActionResult> SignoutAsync(string token, CancellationToken cancellationToken = default)
        {
            if (User == null)
            {
                return ApplicationErrors.NoUserFound.AsResult();
            }

            await Task.CompletedTask;

            return ActionResult.Success;
        }

        /// <summary>
        /// Switch organization
        /// 机构切换
        /// </summary>
        /// <param name="accessor">HTTP accessor</param>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result & new refresh token</returns>
        public virtual async Task<IActionResult> SwitchOrgAsync(IHttpContextAccessor accessor, SwitchOrgRQ rq, CancellationToken cancellationToken = default)
        {
            var (result, newRefeshToken) = await SwitchOrgAsync(rq, cancellationToken);

            if (result.Ok && newRefeshToken != null)
            {
                MinimalApiUtils.OutputRefreshToken(accessor, newRefeshToken);
            }

            return result;
        }

        /// <summary>
        /// Switch organization
        /// 机构切换
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result & new refresh token</returns>
        public virtual async Task<(IActionResult result, string? newRefreshToken)> SwitchOrgAsync(SwitchOrgRQ rq, CancellationToken cancellationToken = default)
        {
            // User logined
            if (User == null)
            {
                return (ApplicationErrors.AccessDenied.AsResult(), null);
            }

            var proxyRQ = new SwitchOrgProxyRQ
            {
                AppId = App.Configuration.AppId,
                AppKey = App.Configuration.AppKey,
                OrganizationId = rq.OrganizationId,
                FromOrganizationId = rq.FromOrganizationId
            };

            // Siganature
            proxyRQ.Sign = proxyRQ.SignWith(App.Configuration.AppSecret);

            try
            {
                var api = $"{App.Configuration.ApiUrl}/Auth/SwitchOrg";

                var client = _clientFactory.CreateClient();
                client.AddAuthorizationHeader(BearerTokenType, rq.Token);

                using var response = await client.PutAsJsonAsync(api, proxyRQ, ModelJsonSerializerContext.Default.SwitchOrgProxyRQ, cancellationToken);

                try
                {
                    response.EnsureSuccessStatusCode();
                }
                catch
                {
                    // Log the response content
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    Logger.LogError("SwitchOrgAsync failed with response: {content}", content);

                    throw;
                }

                var tokenData = await response.Content.ReadFromJsonAsync(ModelJsonSerializerContext.Default.AppTokenData, cancellationToken);

                if (tokenData == null)
                {
                    return (ApplicationErrors.NoDataReturned.AsResult("TokenData"), null);
                }

                var user = await GetUserInfoAsync(tokenData, cancellationToken);
                if (user == null)
                {
                    return (ApplicationErrors.NoDataReturned.AsResult("User"), null);
                }

                // Create the results
                var (service, core, serviceRefreshToken) = await EnrichUserResultsAsync(user, tokenData, cancellationToken);

                if (service.Ok && !string.IsNullOrEmpty(serviceRefreshToken))
                {
                    // Return the core system data
                    if (core != null)
                    {
                        service.Data["core"] = JsonSerializer.Serialize(core, ModelJsonSerializerContext.Default.ApiTokenData);
                    }

                    return (service, serviceRefreshToken);
                }
                else
                {
                    return (service, null);
                }
            }
            catch (Exception ex)
            {
                return (LogException(ex), null);
            }
        }
    }
}

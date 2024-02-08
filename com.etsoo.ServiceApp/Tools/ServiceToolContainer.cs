using com.etsoo.ApiModel.Dto.SmartERP;
using com.etsoo.ApiModel.Dto.SmartERP.MessageQueue;
using com.etsoo.ApiModel.RQ.SmartERP;
using com.etsoo.ApiProxy.Defs;
using com.etsoo.CoreFramework.User;
using com.etsoo.Localization;
using com.etsoo.MessageQueue;
using com.etsoo.ServiceApp.Application;
using com.etsoo.ServiceApp.User;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Globalization;
using System.Net;

namespace com.etsoo.ServiceApp.Tools
{
    /// <summary>
    /// Service container
    /// 服务容器
    /// </summary>
    public class ServiceToolContainer : IServiceToolContainer
    {
        readonly ILogger _logger;
        readonly IServiceApp _app;
        readonly ServiceToolSettings _settings;
        readonly IMessageQueueProducer _messageQueueProducer;
        readonly ISmartERPProxy _smartERPProxy;

        readonly IPAddress _ip;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="logger">Logger</param>
        /// <param name="app">Application</param>
        /// <param name="settings">Settings</param>
        /// <param name="messageQueueProducer">Message queue</param>
        /// <param name="smartERPProxy">SmartERP proxy</param>
        public ServiceToolContainer(
            ILogger logger,
            IServiceApp app,
            ServiceToolSettings settings,
            IMessageQueueProducer messageQueueProducer,
            ISmartERPProxy smartERPProxy
        )
        {
            _logger = logger;
            _app = app;
            _settings = settings;
            _messageQueueProducer = messageQueueProducer;
            _smartERPProxy = smartERPProxy;

            var hostname = Dns.GetHostName();
            var ipEntry = Dns.GetHostEntry(hostname);
            _ip = ipEntry.AddressList.First();
        }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="logger">Logger</param>
        /// <param name="app">Application</param>
        /// <param name="settings">Settings</param>
        /// <param name="messageQueueProducer">Message queue</param>
        /// <param name="smartERPProxy">SmartERP proxy</param>
        [ActivatorUtilitiesConstructor]
        public ServiceToolContainer(
            ILogger<ServiceToolContainer> logger,
            IServiceApp app,
            IConfiguration configuration,
            IMessageQueueProducer messageQueueProducer,
            ISmartERPProxy smartERPProxy
        ) : this(
            logger,
            app,
            configuration.GetSection("AppSettings").Get<ServiceToolSettings>() ?? throw new Exception("No ServiceToolSettings found under AppSettings"),
            messageQueueProducer,
            smartERPProxy
        )
        {
        }

        /// <summary>
        /// Async authorize API service
        /// 异步授权接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="apiService">API service</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>API key</returns>
        public async Task<string?> AuthorizeApiServiceAsync(int globalOrganizationId, int globalUserId, ApiServiceEnum apiService, CancellationToken cancellationToken = default)
        {
            var rq = new ApiServiceRQ { Api = apiService, OrganizationId = globalOrganizationId, UserId = globalUserId };
            var key = await _app.ExchangeDataAsync(rq, ApiModel.ApiModelJsonSerializerContext.Default.ApiServiceRQ);
            return await _smartERPProxy.AuthorizeApiServiceAsync(_app.Configuration.ServiceId, key, cancellationToken);
        }

        /// <summary>
        /// Async authorize API services
        /// 异步授权接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="apiServices">API services</param>
        /// <param name="includeAll">Include all services or not</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>API key</returns>
        public async Task<IEnumerable<string?>?> AuthorizeApiServicesAsync(int globalOrganizationId, int globalUserId, IEnumerable<ApiServiceEnum> apiServices, bool includeAll = false, CancellationToken cancellationToken = default)
        {
            var keys = await Task.WhenAll(apiServices.Select(async api =>
            {
                var rq = new ApiServiceRQ { Api = api, OrganizationId = globalOrganizationId, UserId = globalUserId };
                return await _app.ExchangeDataAsync(rq, ApiModel.ApiModelJsonSerializerContext.Default.ApiServiceRQ);
            }));

            return await _smartERPProxy.AuthorizeApiServicesAsync(new AuthorizeApiServicesRQ
            {
                Id = _app.Configuration.ServiceId,
                Keys = keys,
                IncludeAll = includeAll
            }, cancellationToken);
        }

        /// <summary>
        /// Async authorize SMTP API service
        /// 异步授权SMTP接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<(ApiServiceEnum service, string? key)> AuthorizeSMTPAsync(int globalOrganizationId, int globalUserId, CancellationToken cancellationToken = default)
        {
            var apiServices = new[] { ApiServiceEnum.SMTP, ApiServiceEnum.SMTPDelegation };
            var keys = (await AuthorizeApiServicesAsync(globalOrganizationId, globalUserId, apiServices, false, cancellationToken))?.ToArray();
            var firstKey = keys?.FirstOrDefault(key => !string.IsNullOrEmpty(key));
            if (keys == null || firstKey == null)
            {
                _logger.LogInformation("SMTP AuthorizeApiServiceAsync failed with User {user} from {org}", globalUserId, globalOrganizationId);
                return (apiServices[0], null);
            }

            var index = Array.IndexOf(keys, firstKey);
            return (apiServices[index], firstKey);
        }

        /// <summary>
        /// Async create user
        /// 异步创建用户
        /// </summary>
        /// <param name="orgId">Local organization id</param>
        /// <param name="userId">Local user id</param>
        /// <param name="deviceId">Device id</param>
        /// <param name="culture">Culture</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<T?> CreateUserAsync<T>(int orgId, int userId = 0, int deviceId = 0, string? culture = null, CancellationToken cancellationToken = default) where T : IServiceUser, IServiceUserSelf<T>
        {
            // Query user
            var userDataResult = await _app.GetApiUserDataAsync(orgId, userId, deviceId, cancellationToken);
            if (userDataResult == null || !userDataResult.Ok)
            {
                _logger.LogError("No API User {user} from {org} data found with error {title}", orgId, userId, userDataResult?.Title);
                return default;
            }

            var ci = new CultureInfo(culture ?? _settings.Culture);
            if (!CultureInfo.CurrentCulture.Name.Equals(ci.Name))
                LocalizationUtils.SetCulture(ci);

            var user = T.CreateFromData(userDataResult.Data, _ip, ci, _settings.Region);
            if (user == null)
            {
                _logger.LogError("No User {user} from {org} Created", orgId, userId);
                return default;
            }

            return user;
        }

        /// <summary>
        /// Async create user
        /// 异步创建用户
        /// </summary>
        /// <param name="orgId">Local organization id</param>
        /// <param name="userId">Local user id</param>
        /// <param name="deviceId">Device id</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public Task<T?> CreateUserAsync<T>(int orgId, int userId = 0, int deviceId = 0, CancellationToken cancellationToken = default) where T : IServiceUser, IServiceUserSelf<T>
        {
            return CreateUserAsync<T>(orgId, userId, deviceId, null, cancellationToken);
        }

        /// <summary>
        /// Async send email
        /// 异步发送邮件
        /// </summary>
        /// <param name="apiService">API service</param>
        /// <param name="key">API Key</param>
        /// <param name="data">Email data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Message id</returns>
        public async Task<string> SendEmailAsync(ApiServiceEnum apiService, string key, SendEmailDto data, CancellationToken cancellationToken = default)
        {
            return await _messageQueueProducer.SendEmailAsync(_app.Configuration.ServiceId, apiService, key, data, cancellationToken);
        }
    }
}

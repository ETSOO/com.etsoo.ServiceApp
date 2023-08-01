﻿using com.etsoo.ApiModel.Dto.SmartERP;
using com.etsoo.ApiModel.Dto.SmartERP.MessageQueue;
using com.etsoo.ApiModel.RQ.SmartERP;
using com.etsoo.ApiModel.Utils;
using com.etsoo.ApiProxy.Defs;
using com.etsoo.CoreFramework.User;
using com.etsoo.MessageQueue;
using com.etsoo.ServiceApp.Application;
using Microsoft.Extensions.Logging;
using System.Globalization;
using System.Net;

namespace com.etsoo.ServiceApp.Tools
{
    /// <summary>
    /// Service container
    /// 服务容器
    /// </summary>
    public class ServiceContainer
    {
        readonly ILogger _logger;
        readonly IServiceApp _app;
        readonly ServiceSettings _settings;
        readonly IMessageQueueProducer _messageQueueProducer;
        readonly ISmartERPProxy _smartERPProxy;
        readonly CancellationToken _cancellationToken;

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
        /// <param name="cancellationToken">Cancellation token</param>
        public ServiceContainer(
            ILogger logger,
            IServiceApp app,
            ServiceSettings settings,
            IMessageQueueProducer messageQueueProducer,
            ISmartERPProxy smartERPProxy,
            CancellationToken cancellationToken)
        {
            _logger = logger;
            _app = app;
            _settings = settings;
            _messageQueueProducer = messageQueueProducer;
            _smartERPProxy = smartERPProxy;
            _cancellationToken = cancellationToken;

            var hostname = Dns.GetHostName();
            var ipEntry = Dns.GetHostEntry(hostname);
            _ip = ipEntry.AddressList.First();
        }

        /// <summary>
        /// Async authorize API service
        /// 异步授权接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="apiService">API service</param>
        /// <returns>API key</returns>
        public async Task<string?> AuthorizeApiServiceAsync(int globalOrganizationId, int globalUserId, ApiServiceEnum apiService)
        {
            var rq = new ApiServiceRQ { Api = apiService, OrganizationId = globalOrganizationId, UserId = globalUserId };
            var key = await _app.ExchangeDataAsync(rq);
            return await _smartERPProxy.AuthorizeApiServiceAsync(_app.Configuration.ServiceId, key, _cancellationToken);
        }

        /// <summary>
        /// Async authorize API services
        /// 异步授权接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="apiServices">API services</param>
        /// <param name="includeAll">Include all services or not</param>
        /// <returns>API key</returns>
        public async Task<IEnumerable<string?>?> AuthorizeApiServicesAsync(int globalOrganizationId, int globalUserId, IEnumerable<ApiServiceEnum> apiServices, bool includeAll = false)
        {
            var keys = await Task.WhenAll(apiServices.Select(async api =>
            {
                var rq = new ApiServiceRQ { Api = api, OrganizationId = globalOrganizationId, UserId = globalUserId };
                return await _app.ExchangeDataAsync(rq);
            }));

            return await _smartERPProxy.AuthorizeApiServicesAsync(new AuthorizeApiServicesRQ
            {
                Id = _app.Configuration.ServiceId,
                Keys = keys,
                IncludeAll = includeAll
            }, _cancellationToken);
        }

        /// <summary>
        /// Async authorize SMTP API service
        /// 异步授权SMTP接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <returns>Result</returns>
        public async Task<(ApiServiceEnum service, string key)?> AuthorizeSMTPAsync(int globalOrganizationId, int globalUserId)
        {
            var apiServices = new[] { ApiServiceEnum.SMTP, ApiServiceEnum.SMTPDelegation };
            var keys = (await AuthorizeApiServicesAsync(globalOrganizationId, globalUserId, apiServices))?.ToArray();
            var firstKey = keys?.FirstOrDefault(key => !string.IsNullOrEmpty(key));
            if (keys == null || firstKey == null)
            {
                _logger.LogInformation("SMTP AuthorizeApiServiceAsync failed with User {user} from {org}", globalUserId, globalOrganizationId);
                return null;
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
        /// <returns>Result</returns>
        public async Task<IServiceUser?> CreateUserAsync(int orgId, int userId = 0)
        {
            // Query user
            var userDataResult = await _app.GetApiUserDataAsync(orgId, userId, _cancellationToken);
            if (userDataResult == null || !userDataResult.Ok)
            {
                _logger.LogError("No API User {user} from {org} data found with error {title}", orgId, userId, userDataResult?.Title);
                return null;
            }

            var ci = new CultureInfo(_settings.Culture);
            var user = ServiceUser.CreateFromData(userDataResult.Data, _ip, ci, _settings.Region);
            if (user == null)
            {
                _logger.LogError("No User {user} from {org} Created", orgId, userId);
                return null;
            }

            return user;
        }

        /// <summary>
        /// Async send email
        /// 异步发送邮件
        /// </summary>
        /// <param name="apiService">API service</param>
        /// <param name="key">API Key</param>
        /// <param name="data">Email data</param>
        /// <returns>Message id</returns>
        public async Task<string> SendEmailAsync(ApiServiceEnum apiService, string key, SendEmailDto data)
        {
            var properties = new MessageProperties { AppId = _app.Configuration.ServiceId.ToString(), UserId = key, Type = SmartERPUtils.ApiServiceToType(apiService) };
            var messageId = await _messageQueueProducer.SendJsonAsync(data, properties);
            return messageId;
        }
    }
}

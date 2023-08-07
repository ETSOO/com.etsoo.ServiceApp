﻿using com.etsoo.ApiModel.Dto.SmartERP;
using com.etsoo.ApiModel.Dto.SmartERP.MessageQueue;
using com.etsoo.ApiModel.Utils;
using com.etsoo.MessageQueue;
using System.Text;

namespace com.etsoo.ServiceApp.Tools
{
    /// <summary>
    /// Service tool extentions
    /// 服务工具扩展
    /// </summary>
    public static class ServiceToolExtensions
    {
        /// <summary>
        /// Async send email
        /// 异步发送邮件
        /// </summary>
        /// <param name="producer">Message producer</param>
        /// <param name="serviceId">Service id</param>
        /// <param name="apiService">API service</param>
        /// <param name="key">API Key</param>
        /// <param name="data">Email data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Message id</returns>
        public static async Task<string> SendEmailAsync(this IMessageQueueProducer producer, int serviceId, ApiServiceEnum apiService, string key, SendEmailDto data, CancellationToken cancellationToken = default)
        {
            var properties = new MessageProperties { AppId = serviceId.ToString(), UserId = key, Type = SmartERPUtils.ApiServiceToType(apiService) };
            var messageId = await producer.SendJsonAsync(data, properties, cancellationToken);
            return messageId;
        }

        /// <summary>
        /// Async send operation message
        /// 异步发送操作信息
        /// </summary>
        /// <param name="producer">Message producer</param>
        /// <param name="serviceId">Service id</param>
        /// <param name="operationType">Operation type</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Message id</returns>
        public static async Task<string> SendOperationMessageAsync(this IMessageQueueProducer producer, int serviceId, string operationType, CancellationToken cancellationToken = default)
        {
            var properites = new MessageProperties { AppId = serviceId.ToString(), Type = SmartERPUtils.SmartERPOperationMessageType };
            var messageId = await producer.SendAsync(Encoding.UTF8.GetBytes(operationType), properites, cancellationToken);
            return messageId;
        }
    }
}

using com.etsoo.ApiModel.Dto.SmartERP;
using com.etsoo.ApiModel.Dto.SmartERP.MessageQueue;
using com.etsoo.CoreFramework.User;
using com.etsoo.ServiceApp.User;

namespace com.etsoo.ServiceApp.Tools
{
    /// <summary>
    /// Service container interface
    /// 服务容器接口
    /// </summary>
    public interface IServiceToolContainer
    {
        /// <summary>
        /// Async authorize API service
        /// 异步授权接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="apiService">API service</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>API key</returns>
        Task<string?> AuthorizeApiServiceAsync(int globalOrganizationId, int globalUserId, ApiServiceEnum apiService, CancellationToken cancellationToken = default);

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
        Task<IEnumerable<string?>?> AuthorizeApiServicesAsync(int globalOrganizationId, int globalUserId, IEnumerable<ApiServiceEnum> apiServices, bool includeAll = false, CancellationToken cancellationToken = default);

        /// <summary>
        /// Async authorize SMTP API service
        /// 异步授权SMTP接口服务
        /// </summary>
        /// <param name="globalOrganizationId">Global organization id</param>
        /// <param name="globalUserId">Global user id</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        Task<(ApiServiceEnum service, string? key)> AuthorizeSMTPAsync(int globalOrganizationId, int globalUserId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Async create user
        /// 异步创建用户
        /// </summary>
        /// <param name="orgId">Local organization id</param>
        /// <param name="userId">Local user id</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        Task<T?> CreateUserAsync<T>(int orgId, int userId = 0, CancellationToken cancellationToken = default) where T : IServiceUser, IServiceUserSelf<T>;

        /// <summary>
        /// Async send email
        /// 异步发送邮件
        /// </summary>
        /// <param name="apiService">API service</param>
        /// <param name="key">API Key</param>
        /// <param name="data">Email data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Message id</returns>
        Task<string> SendEmailAsync(ApiServiceEnum apiService, string key, SendEmailDto data, CancellationToken cancellationToken = default);
    }
}

using com.etsoo.CoreFramework.User;
using com.etsoo.Database;
using com.etsoo.ServiceApp.Application;
using com.etsoo.Utils.Actions;

namespace com.etsoo.ServiceApp.Repo
{
    /// <summary>
    /// Shared authorization repository
    /// 共享的授权仓库
    /// </summary>
    public class AuthRepoShared : RepoShared
    {
        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="app">Application</param>
        public AuthRepoShared(IServiceApp app)
            : base(app, "auth")
        {
        }

        /// <summary>
        /// Async exchange token
        /// 异步交换令牌
        /// </summary>
        /// <param name="coreUser">Core user token</param>
        /// <returns>Result</returns>
        public async Task<IActionResult> ExchangeTokenAsync(CurrentUser coreUser)
        {
            // Parameters
            var parameters = new DbParameters();
            parameters.Add("User", coreUser.IdInt);
            parameters.Add("UserUid", coreUser.Uid);
            parameters.Add("UserName", coreUser.Name);
            parameters.Add("Organization", coreUser.Organization);
            parameters.Add("OrganizationName", coreUser.OrganizationName);
            parameters.Add("RoleValue", coreUser.RoleValue);

            var command = CreateCommand(GetCommandName("exchange token"), parameters);
            return await QueryAsResultAsync(command);
        }
    }
}

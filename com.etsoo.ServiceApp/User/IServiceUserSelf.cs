using com.etsoo.CoreFramework.User;
using com.etsoo.Utils.String;
using System.Globalization;
using System.Net;

namespace com.etsoo.ServiceApp.User
{
    /// <summary>
    /// Service user self interface
    /// 服务用户自身接口
    /// </summary>
    /// <typeparam name="TSelf">Self type generic</typeparam>
    public interface IServiceUserSelf<TSelf> : IServiceUser where TSelf : IServiceUserSelf<TSelf>
    {
        /// <summary>
        /// Create user from result data
        /// 从操作结果数据创建用户
        /// </summary>
        /// <param name="data">Result data</param>
        /// <param name="ip">Ip address</param>
        /// <param name="language">Language</param>
        /// <param name="region">Country or region</param>
        /// <returns>User</returns>
        static abstract TSelf? CreateFromData(StringKeyDictionaryObject data, IPAddress ip, CultureInfo language, string region);
    }
}

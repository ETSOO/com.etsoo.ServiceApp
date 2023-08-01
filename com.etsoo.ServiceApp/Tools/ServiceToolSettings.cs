namespace com.etsoo.ServiceApp.Tools
{
    /// <summary>
    /// Service settings
    /// 服务设置
    /// </summary>
    public record ServiceToolSettings
    {
        /// <summary>
        /// Region
        /// 地区
        /// </summary>
        public string Region { get; init; } = "CN";

        /// <summary>
        /// Culture
        /// 文化
        /// </summary>
        public string Culture { get; init; } = "zh-Hans";
    }
}

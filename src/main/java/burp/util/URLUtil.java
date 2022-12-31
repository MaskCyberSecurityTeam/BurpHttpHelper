package burp.util;

/**
 * URL操作工具类 拓展至Hutool-URLUtil
 *
 * @author RichardTang
 */
public class URLUtil extends cn.hutool.core.util.URLUtil {

    /**
     * 获取URIPath部分<br>
     * 如: https://www.mask-sec.com/login?username=aaaa 则获取 https://www.mask-sec.com/login
     *
     * @param URL 需要获取URIPath的URL
     * @return URIPath
     */
    public static String getURIPath(String URL) {
        if (URL.contains("?")) {
            return URL.split("\\?")[0];
        }
        return URL;
    }
}
package burp.util;

public class URLUtil extends cn.hutool.core.util.URLUtil {

    public static String getURIPath(String URL) {
        if (URL.contains("?")) {
            return URL.split("\\?")[0];
        }
        return URL;
    }
}
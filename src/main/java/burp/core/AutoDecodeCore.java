package burp.core;

import cn.hutool.core.text.UnicodeUtil;
import cn.hutool.core.util.ReUtil;
import cn.hutool.core.util.URLUtil;
import cn.hutool.http.HtmlUtil;

/**
 * 解码核心处理类
 *
 * @author RichardTang
 */
public class AutoDecodeCore {

    public static final String HTML_CHR_REGEX = "&#x(.*);";

    public static final String URL_CHR_REGEX = "%[\\w+]{2}";

    public static final String UNICODE_CHR_REGEX = "\\\\u[\\w+]{4}";

    /**
     * 解码html、url、unicode。
     *
     * @param body 需要解码的body
     * @return 解码后的body
     */
    public static String assembly(final String body) {
        String newBody = body;
        if (ReUtil.contains(UNICODE_CHR_REGEX, newBody)) {
            newBody = UnicodeUtil.toString(newBody);
        }
        if (ReUtil.contains(HTML_CHR_REGEX, newBody)) {
            newBody = HtmlUtil.unescape(newBody);
        }
        if (ReUtil.contains(URL_CHR_REGEX, newBody)) {
            newBody = URLUtil.decode(newBody);
        }
        return newBody;
    }
}
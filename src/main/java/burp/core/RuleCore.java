package burp.core;

import burp.bean.Rule;

import java.net.URL;
import java.util.List;
import java.util.Vector;
import java.util.regex.Pattern;

/**
 * 规则匹配核心处理类
 *
 * @author RichardTang
 */
public class RuleCore {

    public static final String ANY = "*";

    public static final String ANY_REGEXP = "(.*)";

    // 存储规则的集合
    public static final Vector<Rule> activeRuleData = new Vector<>();

    public static void assembly(final List<String> metaDataHeaders, final URL url) {
        // 遍历规则
        for (Rule rule : activeRuleData) {

            // 判断当前url是否匹配上现有的规则
            boolean flag = Pattern.compile(rule.getUrl().replace(ANY, ANY_REGEXP))
                    .matcher(url.toExternalForm())
                    .find();

            if (!flag) {
                break;
            }

            // 匹配上，根据规则的动作，进行header的操作。
            String headerName = rule.getHeaderName();
            switch (rule.getAction()) {
                case ADD:
                    addOptionAssembly(metaDataHeaders, headerName, rule.getHeaderValue());
                    break;
                case MODIFY:
                    modifyOptionAssembly(metaDataHeaders, headerName, rule.getHeaderValue());
                    break;
                case REMOVE:
                    removeOptionAssembly(metaDataHeaders, headerName);
                    break;
            }
        }
    }

    /**
     * 新增HttpHeader
     *
     * @param metaDataHeaders 原HttpHeader数据集合
     * @param headerName      新增的HttpHeader
     * @param headerValue     新增的HttpHeaderValue
     */
    public static void addOptionAssembly(final List<String> metaDataHeaders, final String headerName, final String headerValue) {
        metaDataHeaders.add(String.format("%s: %s", headerName, headerValue));
    }

    /**
     * 修改HttpHeader
     *
     * @param metaDataHeaders 原HttpHeader数据集合
     * @param headerName      修改的HttpHeader
     * @param headerValue     修改的HttpHeaderValue
     */
    public static void modifyOptionAssembly(final List<String> metaDataHeaders, final String headerName, final String headerValue) {
        int index = 0;
        for (String header : metaDataHeaders) {
            if (header.contains(headerName)) {
                metaDataHeaders.set(index, String.format("%s: %s", headerName, headerValue));
                break;
            }
            index++;
        }
    }

    /**
     * 删除HttpHeader
     *
     * @param metaDataHeaders 原HttpHeader数据集合
     * @param headerName      需要删除的HttpHeader
     */
    public static void removeOptionAssembly(final List<String> metaDataHeaders, final String headerName) {
        metaDataHeaders.removeIf(header -> header.contains(headerName));
    }

}
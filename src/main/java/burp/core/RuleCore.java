package burp.core;

import burp.bean.Rule;
import burp.constant.RuleTypeOption;

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

    public static final String ANY                = "*";
    public static final String ANY_REGEXP         = "(.*)";
    public static final String COOKIE_HEADER_FLAG = "cookie: ";

    // 存储规则的集合
    public static final Vector<Rule> activeRuleData = new Vector<>();

    public static void assembly(final List<String> metaDataHeaders, final URL url) {
        // 遍历规则
        for (Rule rule : activeRuleData) {

            // 判断当前url是否匹配上现有的规则
            boolean flag = Pattern.compile(rule.getUrl().replace(ANY, ANY_REGEXP)).matcher(url.toExternalForm()).find();
            if (!flag) {
                break;
            }

            // 区分规则要操作的类型
            if (rule.getType() == RuleTypeOption.HEADER) {
                httpHeaderOptionAssembly(rule, metaDataHeaders);
            } else {
                // 遍历所有的头信息
                for (int i = 0; i < metaDataHeaders.size(); i++) {
                    // 找到cookie的头信息
                    String httpHeader = metaDataHeaders.get(i);
                    if (!httpHeader.toLowerCase().startsWith(COOKIE_HEADER_FLAG)) {
                        continue;
                    }
                    // 处理cookie头
                    String newCookie = httpCookieOptionAssembly(rule, httpHeader);
                    // 设置新值
                    metaDataHeaders.set(i, newCookie);
                }
            }
        }
    }

    /**
     * 根据action分发处理HttpCookie
     *
     * @param rule    规则
     * @param cookies 本次要处理的cookie字符串
     * @return 处理后的cookie
     */
    public static String httpCookieOptionAssembly(Rule rule, String cookies) {
        switch (rule.getAction()) {
            case ADD:
                cookies = addHttpCookieOptionAssembly(rule, cookies);
                break;
            case MODIFY:
                cookies = modifyHttpCookieOptionAssembly(rule, cookies);
                break;
            case REMOVE:
                cookies = removeHttpCookieOptionAssembly(rule, cookies);
                break;
        }
        return cookies;
    }

    /**
     * 增加cookie键值对
     *
     * @param rule    规则
     * @param cookies 原cookie键值对信息
     * @return 处理过后的cookie字符串
     */
    public static String addHttpCookieOptionAssembly(Rule rule, String cookies) {
        return String.format("%s %s=%s;", cookies, rule.getKeyName(), rule.getKeyValue());
    }

    /**
     * 修改cookie键值对
     *
     * @param rule    规则
     * @param cookies 原cookie键值对信息
     * @return 处理过后的cookie字符串
     */
    public static String modifyHttpCookieOptionAssembly(Rule rule, String cookies) {
        return Pattern.compile("(?<=" + rule.getKeyName() + "=).+?(?=;)").matcher(cookies).replaceAll(rule.getKeyValue());
    }

    /**
     * 删除cookie键值对
     *
     * @param rule    规则
     * @param cookies 原cookie键值对信息
     * @return 处理过后的cookie字符串
     */
    public static String removeHttpCookieOptionAssembly(Rule rule, String cookies) {
        // TODO cookie必须是标准的 SESSION=123; 如果缺少;号，则匹配不上。
        return Pattern.compile(rule.getKeyName() + "=(.+?;)").matcher(cookies).replaceAll("");
    }

    /**
     * 根据action分发处理HttpHeader
     *
     * @param rule            规则
     * @param metaDataHeaders HttpHeader头集合
     */
    public static void httpHeaderOptionAssembly(Rule rule, final List<String> metaDataHeaders) {
        // 根据规则的动作，对HttpHeader头中的信息进行增删改操作。
        String keyName = rule.getKeyName();
        switch (rule.getAction()) {
            case ADD:
                addHttpHeaderOptionAssembly(metaDataHeaders, keyName, rule.getKeyValue());
                break;
            case MODIFY:
                modifyHttpHeaderOptionAssembly(metaDataHeaders, keyName, rule.getKeyValue());
                break;
            case REMOVE:
                removeHttpHeaderOptionAssembly(metaDataHeaders, keyName);
                break;
        }
    }

    /**
     * 新增HttpHeader
     *
     * @param metaDataHeaders 原HttpHeader数据集合
     * @param headerName      新增的HttpHeader
     * @param headerValue     新增的HttpHeaderValue
     */
    public static void addHttpHeaderOptionAssembly(final List<String> metaDataHeaders, final String headerName, final String headerValue) {
        metaDataHeaders.add(String.format("%s: %s", headerName, headerValue));
    }

    /**
     * 修改HttpHeader
     *
     * @param metaDataHeaders 原HttpHeader数据集合
     * @param headerName      修改的HttpHeader
     * @param headerValue     修改的HttpHeaderValue
     */
    public static void modifyHttpHeaderOptionAssembly(final List<String> metaDataHeaders, final String headerName, final String headerValue) {
        int index = 0;
        for (String header : metaDataHeaders) {
            if (header.toLowerCase().contains(headerName)) {
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
     * @param headerName      需要删除的HttpHeaderName
     */
    public static void removeHttpHeaderOptionAssembly(final List<String> metaDataHeaders, final String headerName) {
        metaDataHeaders.removeIf(header -> header.equalsIgnoreCase(headerName));
    }
}
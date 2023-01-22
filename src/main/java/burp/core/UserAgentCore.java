package burp.core;

import burp.Gui;

import java.util.*;

/**
 * UserAgent核心处理类
 *
 * @author RichardTang
 */
public class UserAgentCore {

    // 存储PC端UserAgent
    public static final LinkedList<String> pcUserAgent = new LinkedList<>();

    // 存储Mobile端UserAgent
    public static final LinkedList<String> mobileUserAgent = new LinkedList<>();

    /**
     * 处理类
     *
     * @param headers 原HttpHeader
     * @param gui     主页面
     */
    public static void assembly(final List<String> headers, Gui gui) {
        String userAgent = null;
        // PC和Mobile选项都勾选
        if (gui.getUserAgentPanel().getPcCheckBox().isSelected() && gui.getUserAgentPanel().getMobileCheckBox().isSelected()) {
            userAgent = getRandomUserAgent();
        }
        // 只勾选PC
        else if (gui.getUserAgentPanel().getPcCheckBox().isSelected()) {
            userAgent = getRandomPcUserAgent();
        }
        // 只勾选Mobile
        else if (gui.getUserAgentPanel().getMobileCheckBox().isSelected()) {
            userAgent = getRandomMobileUserAgent();
        }

        // 以上都没有勾选，那么就不进行修改，userAgent有值就代表修改了。
        if (userAgent != null) {
            RuleCore.modifyHttpHeaderOptionAssembly(headers, "User-Agent", userAgent);
        }
    }

    /**
     * 随机生成PC和Mobile的UserAgent
     *
     * @return 随机生成的UserAgent
     */
    public static String getRandomUserAgent() {
        if (mobileUserAgent.size() == 0 || pcUserAgent.size() == 0) {
            return null;
        }
        int i = (int) (Math.random() * 2);
        if (i == 0) {
            return getRandomPcUserAgent();
        } else {
            return getRandomMobileUserAgent();
        }
    }

    /**
     * 随机生成PC的UserAgent
     *
     * @return 随机生成的PC UserAgent
     */
    public static String getRandomPcUserAgent() {
        if (pcUserAgent.size() == 0) {
            return null;
        }
        int i = (int) (Math.random() * pcUserAgent.size());
        return pcUserAgent.get(i);
    }

    /**
     * 随机生成Mobile的UserAgent
     *
     * @return 随机生成的Mobile UserAgent
     */
    public static String getRandomMobileUserAgent() {
        if (mobileUserAgent.size() == 0) {
            return null;
        }
        int i = (int) (Math.random() * mobileUserAgent.size());
        return mobileUserAgent.get(i);
    }
}

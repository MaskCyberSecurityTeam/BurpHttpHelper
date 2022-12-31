package burp.core;

import burp.Gui;

import java.util.*;

public class UserAgentCore {

    public static final LinkedList<String> pcUserAgent = new LinkedList<>();

    public static final LinkedList<String> mobileUserAgent = new LinkedList<>();

    public static void assembly(final List<String> headers, Gui gui) {
        String userAgent = null;
        if (gui.getUserAgentPanel().getPcCheckBox().isSelected() && gui.getUserAgentPanel().getMobileCheckBox().isSelected()) {
            userAgent = getRandomUserAgent();
        } else if (gui.getUserAgentPanel().getPcCheckBox().isSelected()) {
            userAgent = getRandomPcUserAgent();
        } else if (gui.getUserAgentPanel().getMobileCheckBox().isSelected()) {
            userAgent = getRandomMobileUserAgent();
        }
        if (userAgent != null) {
            RuleCore.modifyOptionAssembly(headers, "User-Agent", userAgent);
        }
    }

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

    public static String getRandomPcUserAgent() {
        if (pcUserAgent.size() == 0) {
            return null;
        }
        int i = (int) (Math.random() * pcUserAgent.size());
        return pcUserAgent.get(i);
    }

    public static String getRandomMobileUserAgent() {
        if (mobileUserAgent.size() == 0) {
            return null;
        }
        int i = (int) (Math.random() * mobileUserAgent.size());
        return mobileUserAgent.get(i);
    }
}

package burp.ui.component;

import burp.IBurpExtenderCallbacks;
import burp.constant.ConfigKey;
import burp.util.FileUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import javax.swing.*;
import java.io.File;
import java.nio.charset.StandardCharsets;

/**
 * 通用Panel
 *
 * @author RichardTang
 */
public abstract class BurpPanel extends JPanel {

    // 配置文件绝对路径
    private String configFilePath;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    /**
     * 空参构造，用于lombok生成代码，实际的BurpPanel子类，应继承有参数的那个构造函数。
     */
    protected BurpPanel() {

    }

    public BurpPanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        this.configFilePath = FileUtil.getConfigFilePathByBurpExt(iBurpExtenderCallbacks);

        // 初始化动作
        initComponent();
        initEvent();
        loadConfigFile();
    }

    /**
     * 初始化组件
     */
    public abstract void initComponent();

    /**
     * 初始化事件
     */
    public abstract void initEvent();

    /**
     * 初始化配置
     *
     * @param rootJSONObject 当前这个Panel在配置文件中对应的JSONObject部分配置
     */
    public abstract void initConfig(JSONObject rootJSONObject);

    /**
     * 在配置文件中的根key
     *
     * @return 根key值
     */
    public abstract String rootJSONObjectKey();

    /**
     * 加载配置文件，会根据rootJSONObjectKey来找到属于当前这个Panel的JSONObject。
     */
    public void loadConfigFile() {
        File configFile = new File(configFilePath);
        if (configFile.exists()) {
            try {
                String rootKey = rootJSONObjectKey();
                // 如果rootKey为null，则代表当前这个Panel在配置文件中没有配置。
                if (rootKey == null) {
                    return;
                } else {
                    // 存在配置的情况下，则进行读取配置。
                    JSONObject rootJSONObject = JSONUtil.readJSONObject(configFile, StandardCharsets.UTF_8).getJSONObject(rootKey);
                    initConfig(rootJSONObject);
                }
            } catch (Exception e) {
                iBurpExtenderCallbacks.printOutput("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput(e.getMessage());
            }
        }
    }
}
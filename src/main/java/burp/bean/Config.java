package burp.bean;

import lombok.Data;

import java.util.HashMap;

/**
 * 配置类
 *
 * @author RichardTang
 */
@Data
public class Config {

    // 规则面板配置
    private final HashMap<String, Object> rulePanelConfig = new HashMap<>();

    // UA面板配置
    private final HashMap<String, Object> userAgentPanelConfig = new HashMap<>();

}
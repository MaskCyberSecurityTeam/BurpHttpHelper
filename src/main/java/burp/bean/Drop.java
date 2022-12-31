package burp.bean;

import lombok.Builder;
import lombok.Data;

/**
 * 丢弃数据包
 *
 * @author RichardTang
 */
@Data
@Builder
public class Drop {

    // 编号
    private Integer id;

    // 匹配的地址ß
    private String url;

    // 备注
    private String comment;
}
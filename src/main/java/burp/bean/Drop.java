package burp.bean;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Drop {

    private Integer id;

    private String url;

    private String comment;
}

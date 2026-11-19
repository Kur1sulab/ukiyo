# 白主题对比度实测（contrast.py --batch，40 对全过）

| 色对（用途） | 实测 | 门槛 | 等级 | 结果 |
|---|---|---|---|---|
| text on bg [#16181C on #F4F5F6] | 16.28:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on bg [#52575E on #F4F5F6] | 6.67:1 | ≥4.5 | AA ✓ | ✅ |
| faint on bg [#676D76 on #F4F5F6] | 4.78:1 | ≥4.5 | AA ✓ | ✅ |
| future on bg [#68696B on #F4F5F6] | 5.03:1 | ≥4.5 | AA ✓ | ✅ |
| text on panel [#16181C on #FFFFFF] | 17.77:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on panel [#52575E on #FFFFFF] | 7.28:1 | ≥4.5 | AAA ✓✓ | ✅ |
| faint on panel [#676D76 on #FFFFFF] | 5.22:1 | ≥4.5 | AA ✓ | ✅ |
| future on panel [#68696B on #FFFFFF] | 5.50:1 | ≥4.5 | AA ✓ | ✅ |
| text on panel-2 [#16181C on #EFF0F2] | 15.59:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on panel-2 [#52575E on #EFF0F2] | 6.39:1 | ≥4.5 | AA ✓ | ✅ |
| faint on panel-2 [#676D76 on #EFF0F2] | 4.57:1 | ≥4.5 | AA ✓ | ✅ |
| future on panel-2 [#68696B on #EFF0F2] | 4.82:1 | ≥4.5 | AA ✓ | ✅ |
| text on tint-ok [#16181C on #EFF6F1] | 16.18:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on tint-ok [#52575E on #EFF6F1] | 6.63:1 | ≥4.5 | AA ✓ | ✅ |
| text on tint-warn [#16181C on #F7F4ED] | 16.18:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on tint-warn [#52575E on #F7F4ED] | 6.63:1 | ≥4.5 | AA ✓ | ✅ |
| text on tint-bad [#16181C on #FBF1F1] | 16.04:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on tint-bad [#52575E on #FBF1F1] | 6.57:1 | ≥4.5 | AA ✓ | ✅ |
| ok 数字 on panel [#1F7A3D on #FFFFFF] | 5.37:1 | ≥4.5 | AA ✓ | ✅ |
| ok 圆点 on panel [#1F7A3D on #FFFFFF] | 5.37:1 | ≥3.0 | AAA ✓✓ | ✅ |
| ok 圆点 on panel-2 [#1F7A3D on #EFF0F2] | 4.71:1 | ≥3.0 | AAA ✓✓ | ✅ |
| edge-ok 1px边框 vs panel [#679072 on #FFFFFF] | 3.62:1 | ≥3.0 | AA ✓ | ✅ |
| edge-ok 1px边框 vs tint-ok [#679072 on #EFF6F1] | 3.29:1 | ≥3.0 | AA ✓ | ✅ |
| warn 数字 on panel [#8F6400 on #FFFFFF] | 5.26:1 | ≥4.5 | AA ✓ | ✅ |
| warn 圆点 on panel [#8F6400 on #FFFFFF] | 5.26:1 | ≥3.0 | AAA ✓✓ | ✅ |
| warn 圆点 on panel-2 [#8F6400 on #EFF0F2] | 4.61:1 | ≥3.0 | AAA ✓✓ | ✅ |
| edge-warn 1px边框 vs panel [#98865E on #FFFFFF] | 3.56:1 | ≥3.0 | AA ✓ | ✅ |
| edge-warn 1px边框 vs tint-warn [#98865E on #F7F4ED] | 3.24:1 | ≥3.0 | AA ✓ | ✅ |
| bad 数字 on panel [#C0303C on #FFFFFF] | 5.63:1 | ≥4.5 | AA ✓ | ✅ |
| bad 圆点 on panel [#C0303C on #FFFFFF] | 5.63:1 | ≥3.0 | AAA ✓✓ | ✅ |
| bad 圆点 on panel-2 [#C0303C on #EFF0F2] | 4.94:1 | ≥3.0 | AAA ✓✓ | ✅ |
| edge-bad 1px边框 vs panel [#A57A7E on #FFFFFF] | 3.69:1 | ≥3.0 | AA ✓ | ✅ |
| edge-bad 1px边框 vs tint-bad [#A57A7E on #FBF1F1] | 3.33:1 | ≥3.0 | AA ✓ | ✅ |
| line-strong vs bg [#848587 on #F4F5F6] | 3.38:1 | ≥3.0 | AA ✓ | ✅ |
| line-strong vs panel [#848587 on #FFFFFF] | 3.69:1 | ≥3.0 | AA ✓ | ✅ |
| line-strong vs panel-2 [#848587 on #EFF0F2] | 3.24:1 | ≥3.0 | AA ✓ | ✅ |
| on-primary on primary [#FFFFFF on #16181C] | 17.77:1 | ≥4.5 | AAA ✓✓ | ✅ |
| text on glass(合成) [#16181C on #FFFFFF] | 17.77:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on glass(合成) [#52575E on #FFFFFF] | 7.28:1 | ≥4.5 | AAA ✓✓ | ✅ |
| faint on glass(合成) [#676D76 on #FFFFFF] | 5.22:1 | ≥4.5 | AA ✓ | ✅ |

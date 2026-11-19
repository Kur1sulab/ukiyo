# 黑主题对比度实测（contrast.py --batch，40 对全过）

| 色对（用途） | 实测 | 门槛 | 等级 | 结果 |
|---|---|---|---|---|
| text on bg [#EDEFF2 on #0A0C0F] | 17.00:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on bg [#A9AFB8 on #0A0C0F] | 8.87:1 | ≥4.5 | AAA ✓✓ | ✅ |
| faint on bg [#8F96A0 on #0A0C0F] | 6.56:1 | ≥4.5 | AA ✓ | ✅ |
| future on bg [#8C8E91 on #0A0C0F] | 5.96:1 | ≥4.5 | AA ✓ | ✅ |
| text on panel [#EDEFF2 on #15171A] | 15.59:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on panel [#A9AFB8 on #15171A] | 8.13:1 | ≥4.5 | AAA ✓✓ | ✅ |
| faint on panel [#8F96A0 on #15171A] | 6.02:1 | ≥4.5 | AA ✓ | ✅ |
| future on panel [#8C8E91 on #15171A] | 5.47:1 | ≥4.5 | AA ✓ | ✅ |
| text on panel-2 [#EDEFF2 on #1F2123] | 14.02:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on panel-2 [#A9AFB8 on #1F2123] | 7.32:1 | ≥4.5 | AAA ✓✓ | ✅ |
| faint on panel-2 [#8F96A0 on #1F2123] | 5.41:1 | ≥4.5 | AA ✓ | ✅ |
| future on panel-2 [#8C8E91 on #1F2123] | 4.92:1 | ≥4.5 | AA ✓ | ✅ |
| text on tint-ok [#EDEFF2 on #1A2422] | 13.82:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on tint-ok [#A9AFB8 on #1A2422] | 7.21:1 | ≥4.5 | AAA ✓✓ | ✅ |
| text on tint-warn [#EDEFF2 on #25221B] | 13.78:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on tint-warn [#A9AFB8 on #25221B] | 7.19:1 | ≥4.5 | AAA ✓✓ | ✅ |
| text on tint-bad [#EDEFF2 on #251D20] | 14.29:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on tint-bad [#A9AFB8 on #251D20] | 7.46:1 | ≥4.5 | AAA ✓✓ | ✅ |
| ok 数字 on panel [#58B87A on #15171A] | 7.31:1 | ≥4.5 | AAA ✓✓ | ✅ |
| ok 圆点 on panel [#58B87A on #15171A] | 7.31:1 | ≥3.0 | AAA ✓✓ | ✅ |
| ok 圆点 on panel-2 [#58B87A on #1F2123] | 6.58:1 | ≥3.0 | AAA ✓✓ | ✅ |
| edge-ok 1px边框 vs panel [#4A7A5E on #15171A] | 3.62:1 | ≥3.0 | AA ✓ | ✅ |
| edge-ok 1px边框 vs tint-ok [#4A7A5E on #1A2422] | 3.21:1 | ≥3.0 | AA ✓ | ✅ |
| warn 数字 on panel [#D9A521 on #15171A] | 8.00:1 | ≥4.5 | AAA ✓✓ | ✅ |
| warn 圆点 on panel [#D9A521 on #15171A] | 8.00:1 | ≥3.0 | AAA ✓✓ | ✅ |
| warn 圆点 on panel-2 [#D9A521 on #1F2123] | 7.20:1 | ≥3.0 | AAA ✓✓ | ✅ |
| edge-warn 1px边框 vs panel [#836E42 on #15171A] | 3.66:1 | ≥3.0 | AA ✓ | ✅ |
| edge-warn 1px边框 vs tint-warn [#836E42 on #25221B] | 3.23:1 | ≥3.0 | AA ✓ | ✅ |
| bad 数字 on panel [#E0606A on #15171A] | 5.17:1 | ≥4.5 | AA ✓ | ✅ |
| bad 圆点 on panel [#E0606A on #15171A] | 5.17:1 | ≥3.0 | AAA ✓✓ | ✅ |
| bad 圆点 on panel-2 [#E0606A on #1F2123] | 4.65:1 | ≥3.0 | AAA ✓✓ | ✅ |
| edge-bad 1px边框 vs panel [#915B63 on #15171A] | 3.32:1 | ≥3.0 | AA ✓ | ✅ |
| edge-bad 1px边框 vs tint-bad [#915B63 on #251D20] | 3.04:1 | ≥3.0 | AA ✓ | ✅ |
| line-strong vs bg [#717274 on #0A0C0F] | 4.07:1 | ≥3.0 | AA ✓ | ✅ |
| line-strong vs panel [#717274 on #15171A] | 3.73:1 | ≥3.0 | AA ✓ | ✅ |
| line-strong vs panel-2 [#717274 on #1F2123] | 3.35:1 | ≥3.0 | AA ✓ | ✅ |
| on-primary on primary [#0A0C0F on #EDEFF2] | 17.00:1 | ≥4.5 | AAA ✓✓ | ✅ |
| text on glass(合成) [#EDEFF2 on #0F1114] | 16.41:1 | ≥4.5 | AAA ✓✓ | ✅ |
| muted on glass(合成) [#A9AFB8 on #0F1114] | 8.56:1 | ≥4.5 | AAA ✓✓ | ✅ |
| faint on glass(合成) [#8F96A0 on #0F1114] | 6.34:1 | ≥4.5 | AA ✓ | ✅ |

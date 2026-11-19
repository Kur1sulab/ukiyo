#!/usr/bin/env python3
"""从 replay.css 的真实 token 生成 contrast.py 批量色对表（黑/白各一份）。
半透明色一律先合成到实际承载背景上再送测（与浏览器渲染一致）。"""
import re, pathlib

HERE = pathlib.Path(__file__).resolve().parent
CSS = (HERE.parent / 'replay.css').read_text()

def tokens(theme):
    block = re.search(r'\[data-theme="%s"\]\s*\{(.*?)\}' % theme, CSS, re.S).group(1)
    out = {}
    for m in re.finditer(r'--([\w-]+):\s*([^;]+);', block):
        out[m.group(1)] = m.group(2).strip()
    return out

def parse(c):
    c = c.strip()
    m = re.match(r'rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+))?\s*\)', c)
    if m:
        r, g, b = (float(m.group(i)) for i in (1, 2, 3))
        a = float(m.group(4)) if m.group(4) else 1.0
        return (r, g, b, a)
    h = c.lstrip('#')
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0)

def hexs(rgb):
    return '#%02X%02X%02X' % tuple(int(round(v)) for v in rgb[:3])

def blend(fg, over):
    f, o = parse(fg), parse(over)
    a = f[3]
    return hexs(tuple(f[i] * a + o[i] * (1 - a) for i in range(3)))

def resolve(t, name, over='panel'):
    """token → 实色 hex；半透明 token 合成到 over（默认 panel）上。"""
    v = t[name]
    p = parse(v)
    if p[3] >= 0.999:
        return hexs(p)
    base = t[over] if over in t else over
    return blend(v, resolve(t, over) if over in t else base)

pairs = []
def add(label, fg, bg, large=False):
    pairs.append((label, fg, bg, large))

for theme in ('dark', 'light'):
    t = tokens(theme)
    R = lambda n, over='panel': resolve(t, n, over)
    lines = [f'# ===== {theme} 主题（token 实测，半透明已合成） =====']
    P = []
    def a(label, fg, bg, large=False):
        P.append((label, fg, bg, large))
    # 正文/次级/弱文字 × 三种承载背景
    for bgname in ('bg', 'panel', 'panel-2'):
        for fgname in ('text', 'muted', 'faint', 'future'):
            a(f'{fgname} on {bgname}', R(fgname, bgname), R(bgname))
    # 判定徽章/横幅：中性文字 on 极淡语义底
    for tone in ('ok', 'warn', 'bad'):
        a(f'text on tint-{tone}', R('text', f'tint-{tone}'), R(f'tint-{tone}'))
        a(f'muted on tint-{tone}', R('muted', f'tint-{tone}'), R(f'tint-{tone}'))
    # 语义色小面积：数字着色（15px bold，按正文 4.5）+ 圆点/边框（非文本 3:1）
    for tone in ('ok', 'warn', 'bad'):
        a(f'{tone} 数字 on panel', R(tone), R('panel'))
        a(f'{tone} 圆点 on panel', R(tone), R('panel'), True)
        a(f'{tone} 圆点 on panel-2', R(tone), R('panel-2'), True)
        a(f'edge-{tone} 1px边框 vs panel', R(f'edge-{tone}'), R('panel'), True)
        a(f'edge-{tone} 1px边框 vs tint-{tone}', R(f'edge-{tone}', f'tint-{tone}'), R(f'tint-{tone}'), True)
    # 交互边界/焦点环（非文本 3:1）
    for bgname in ('bg', 'panel', 'panel-2'):
        a(f'line-strong vs {bgname}', R('line-strong', bgname), R(bgname), True)
    # 主按钮（播放中）：on-primary on primary
    a('on-primary on primary', R('on-primary', 'primary'), R('primary'))
    # 玻璃工具条上的文字：glass 合成到 panel（工具条悬浮于面板区）
    glass = blend(t['glass'], R('panel'))
    for fgname in ('text', 'muted', 'faint'):
        a(f'{fgname} on glass(合成)', R(fgname, 'panel'), glass)
    # 选中态/按钮底上的文字已含于 panel-2 组；dossier 表格 td=muted/th=text 同上
    def rgbfmt(h):
        p = parse(h)
        return 'rgb(%d,%d,%d)' % tuple(int(round(v)) for v in p[:3])
    for label, fg, bg, large in P:
        # 注意：contrast.py 批处理把 '#' 开头的行当注释，故用 rgb() 格式
        lines.append(f'{rgbfmt(fg)} {rgbfmt(bg)}' + (' large' if large else '') + f'   # {label} [{fg} on {bg}]')
    (HERE / f'pairs-{theme}.txt').write_text('\n'.join(lines) + '\n')
    print(theme, 'pairs:', len(P))

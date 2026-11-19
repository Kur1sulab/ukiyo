#!/usr/bin/env python3
"""自测：三类带外 token 必须在**不出站**的前提下真被触发。

测的不是「函数能跑」，是四件在部署里会要命的事：

  1. DNS 解析即回调 —— 对方只需要 `getent hosts`，不需要连我们任何 TCP 端口。
     同时验证反放大：NXDOMAIN 响应长度必须 == 查询长度（1:1，不能当反射器）。
  2. AWS key 静态不可识别 —— 长度/字符集/熵/无标记/不与官方示例 key 撞车，
     且**每会话唯一**。然后真签一次 SigV4 GetCallerIdentity 打进来，要求
     本地验签通过（证明它用的是真签名器，不是 grep 出来的字符串）。
  3. MCP tool-call-only —— initialize / tools/list 只算「摸到了」，
     只有 tools/call 进告警。这条分界线写错，整个指标就废了。
  4. 全程出站 == 0 —— NoEgressGuard 拦 connect/create_connection/getaddrinfo/
     非应答 sendto，任何一次尝试都会让本次自测失败。红线是测试，不是注释。

SigV4 签名在测试里**独立实现**一份（不调用被测模块的验签路径），
否则同一个 bug 会在签名和验签两侧对称出现，测试永远绿。

用法：python3 _selftest_oob.py    （全过退出码 0，任一失败退出码 1）
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import socket
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honey_demo as hd
import honey_oob as oob
import honey_state
from honey_server import Honeypot

results: list[bool] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append(bool(ok))
    print(f"  [{'✅' if ok else '❌'}] {label}" + (f"　{detail}" if detail else ""))


# ---------------------------------------------------------------------------
# 独立 SigV4 签名器（AWS 文档算法逐步实现，不复用被测代码）
# ---------------------------------------------------------------------------
def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hm(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign_v4(akid: str, secret: str, *, host: str, body: bytes, path: str = "/sts",
            region: str = "cn-north-1", service: str = "sts") -> dict[str, str]:
    amzdate = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    date = amzdate[:8]
    ctype = "application/x-www-form-urlencoded; charset=utf-8"
    hdrs = {"content-type": ctype, "host": host, "x-amz-date": amzdate}
    signed = ["content-type", "host", "x-amz-date"]
    canon_headers = "".join(f"{k}:{hdrs[k]}\n" for k in signed)
    canon_req = "\n".join(["POST", path, "", canon_headers, ";".join(signed), _sha(body)])
    scope = f"{date}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, _sha(canon_req.encode())])
    k = _hm(("AWS4" + secret).encode(), date)
    k = _hm(k, region)
    k = _hm(k, service)
    k = _hm(k, "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return {"Authorization": f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, "
                             f"SignedHeaders={';'.join(signed)}, Signature={sig}",
            "Content-Type": ctype, "X-Amz-Date": amzdate, "Signature": sig}


# ---------------------------------------------------------------------------
# 原始 DNS 查询（UDP，不经 resolver —— 本机 libc 解析器会走 mDNS，不可控）
# ---------------------------------------------------------------------------
def dns_query(name: str, qtype: int = 1, ident: int = 0x4B1D) -> bytes:
    pkt = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        pkt += bytes([len(lab)]) + lab.encode()
    return pkt + b"\x00" + struct.pack("!HH", qtype, 1)


def dns_ask(port: int, name: str, qtype: int = 1) -> tuple[bytes, bytes]:
    q = dns_query(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(q, ("127.0.0.1", port))
        return q, s.recvfrom(512)[0]
    finally:
        s.close()


def rcode(resp: bytes) -> int:
    return struct.unpack("!H", resp[2:4])[0] & 0xF


def http_post(port: int, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("POST", path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace"), dict(r.getheaders())
    finally:
        conn.close()


def fetch_from(src_ip: str, port: int, path: str) -> tuple[int, str]:
    """从指定源地址取一个路径（保留给需要「第二个会话」的场景）。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10,
                                      source_address=(src_ip, 0))
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


def main() -> int:
    world = hd.make_world()
    d = tempfile.mkdtemp(prefix="ukiyo-oob-")
    hp = Honeypot(world=world, http_port=hd._free_port(), ssh_port=None,
                  ledger_path=os.path.join(d, "oob.jsonl"), enable_ssh=False,
                  oob_zone="archive-node01.corp.internal")
    guard = oob.NoEgressGuard()

    print("\n=== 1. 工件：带外 token 是否真的出现在世界里 ===")
    with guard:
        hp.start()
        try:
            base = f"http://127.0.0.1:{hp.http_port}"
            P = world.probe_paths()
            c = hd.Client(base, hd.UA_AGENT)
            c.get("/")
            st_cred, cred = c.get(f"/files/../..{P['creds'].rsplit('/', 1)[0]}/credentials")
            st_conf, conf = c.get(f"/files/../..{P['creds']}")
            st_mcp, mcp_txt = c.get("/files/../../home/ops_zhao/.config/mcp/mcp.json")
            st_notes, notes = c.get(f"/files/../..{P['notes']}")

            check("三件带外工件可读", (st_cred, st_conf, st_mcp) == (200, 200, 200),
                  f"credentials={st_cred} config={st_conf} mcp={st_mcp}")

            akid = ""
            secret = ""
            for line in cred.splitlines():
                if "aws_access_key_id" in line:
                    akid = line.split("=", 1)[1].strip()
                if "aws_secret_access_key" in line:
                    secret = line.split("=", 1)[1].strip()

            bad = oob.static_detectability(akid, secret, extra_words=(world.hostname,))
            check("AWS key 通过静态不可检测检查（长度/字符集/熵/无标记/不与示例 key 撞车）",
                  not bad, "9 项全过" if not bad else f"命中 {bad}")
            check("AWS key 形状正确", len(akid) == 20 and akid.startswith("AKIA") and len(secret) == 40,
                  f"AKID {len(akid)} 位 / secret {len(secret)} 位")
            check("credentials 文件里没有蜜标痕迹",
                  "/c/" not in cred and "canary" not in cred.lower() and "..." not in cred,
                  "无 /c/ 回调、无 canary 字样、无省略号占位")
            check("config 保留旧回调链路（身份外带上报口不能被新能力顶掉）",
                  "/c/" in conf, f"旧 endpoint 仍在")
            check("config 新增内网 STS profile（第二条触发路径）",
                  "/sts" in conf and "profile archive-sync" in conf,
                  conf.strip().splitlines()[-1])

            # 每会话唯一 + 同会话稳定：token 每请求轮换会让归因直接失效
            import honey_state
            sa = honey_state.Session("10.10.0.5", hd.UA_AGENT)
            sb = honey_state.Session("10.10.0.6", hd.UA_AGENT)
            keypath = f"{P['creds'].rsplit('/', 1)[0]}/credentials"

            def akid_of(sess):
                txt = hp.oob_artifacts(sess)[keypath]
                return [ln.split("=", 1)[1].strip() for ln in txt.splitlines()
                        if "aws_access_key_id" in ln][0]

            a1, a2, b1 = akid_of(sa), akid_of(sa), akid_of(sb)
            check("同会话重复取件拿到同一把 key（不轮换 → 归因稳定）", a1 == a2,
                  f"…{a1[-4:]} == …{a2[-4:]}")
            check("不同会话拿到不同 key（每会话唯一）", a1 != b1,
                  f"会话 A …{a1[-4:]} / 会话 B …{b1[-4:]}")

            mcp_json = json.loads(mcp_txt)
            mcp_tok = mcp_json["mcpServers"]["archiver-ops"]["headers"]["Authorization"].split()[-1]
            check("mcp.json 结构合法且嵌了 Bearer token",
                  mcp_tok.startswith("mcp_") and len(mcp_tok) > 30,
                  f"{len(mcp_json['mcpServers'])} 个 server / token {mcp_tok[:8]}…")

            # -------------------------------------------------------------------
            print("\n=== 2. DNS token：解析即回调，且不能当反射器 ===")
            dns_names = [ln for ln in notes.splitlines() if "getent hosts" in ln]
            zone_label = ""
            if dns_names:
                zone_label = dns_names[0].split("getent hosts ")[1].split("`")[0].strip()
            check("运维便签给出了 DNS 自检名（自然的触发理由）", bool(zone_label), zone_label)

            before = len(hp.oob.alerts())
            q, resp = dns_ask(hp.dns.port, zone_label)
            after = len(hp.oob.alerts())
            check("DNS 查询被识别为命中", after == before + 1,
                  f"alerts {before}→{after}，rcode={rcode(resp)}(NXDOMAIN)")
            check("响应是 NXDOMAIN（只记录不解析）", rcode(resp) == 3, f"rcode={rcode(resp)}")
            check("反放大：响应长度 == 查询长度", len(resp) == len(q),
                  f"query={len(q)}B resp={len(resp)}B")
            dns_hit = [e for e in hp.oob.events if e["kind"] == oob.KIND_DNS][-1]
            check("命中带上了 qname/qtype/来源端口",
                  dns_hit["evidence"].get("qtype") == "A" and dns_hit["evidence"].get("qname"),
                  f"{dns_hit['evidence'].get('qname')} {dns_hit['evidence'].get('qtype')}")

            # 带 payload 的子域：攻击者常把 hostname 编进 label，这是身份外带
            payload_name = zone_label.replace(".", ".web01.", 1)
            dns_ask(hp.dns.port, payload_name)
            ev = [e for e in hp.oob.events if e["kind"] == oob.KIND_DNS][-1]["evidence"]
            check("子域 payload 被记录（身份外带证据）", "web01" in ev.get("payload_labels", ""),
                  f"payload_labels={ev.get('payload_labels')}")

            n_before = hp.oob.counts["unissued"]
            _, resp_unknown = dns_ask(hp.dns.port, "nothing-here.example")
            check("未知域名不产生告警，只计 noise",
                  rcode(resp_unknown) == 3 and hp.oob.counts["unissued"] == n_before + 1,
                  f"unissued {n_before}→{hp.oob.counts['unissued']}")

            # sinkhole 模式：已知 token 回一条 A 记录，把对方拉回 HTTP 面做后续观察
            sink2 = oob.DnsSink(hp.oob, bind="127.0.0.1", port=0, answer_ip="203.0.113.7")
            sink2.start()
            try:
                _, resp_sh = dns_ask(sink2.port, zone_label)
            finally:
                sink2.stop()
            ancount = struct.unpack("!H", resp_sh[6:8])[0]
            check("sinkhole 模式：已知 token 回 A 记录（可选，把对方拉回 HTTP 面）",
                  rcode(resp_sh) == 0 and ancount == 1 and resp_sh[-4:] == bytes([203, 0, 113, 7]),
                  f"rcode={rcode(resp_sh)} an={ancount} ip={'.'.join(map(str, resp_sh[-4:]))}")

            # 畸形报文：qdcount=2 / 压缩指针 —— 必须丢弃，不能放大
            bad1 = struct.pack("!HHHHHH", 1, 0x0100, 2, 0, 0, 0) + b"\x03abc\x00"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.6)
            s.sendto(bad1, ("127.0.0.1", hp.dns.port))
            try:
                s.recvfrom(512)
                got_reply = True
            except socket.timeout:
                got_reply = False
            s.close()
            check("QDCOUNT≠1 的畸形查询被丢弃（不可作放大器）", not got_reply,
                  f"dropped={hp.dns.dropped}")

            # -------------------------------------------------------------------
            print("\n=== 3. AWS key：只有真签一次 GetCallerIdentity 才响 ===")
            body = b"Action=GetCallerIdentity&Version=2011-06-15"
            host = f"127.0.0.1:{hp.http_port}"
            hdrs = sign_v4(akid, secret, host=host, body=body)
            sig = hdrs.pop("Signature")
            n0 = len([e for e in hp.oob.alerts() if e["kind"] == oob.KIND_AWS])
            st, xml, _ = http_post(hp.http_port, "/sts", body, hdrs)
            aws_hits = [e for e in hp.oob.alerts() if e["kind"] == oob.KIND_AWS]
            check("合法 SigV4 请求返回 200 + GetCallerIdentity", st == 200 and
                  "GetCallerIdentityResult" in xml, f"status={st}")
            check("命中被记为告警（且只有一条）", len(aws_hits) == n0 + 1,
                  f"aws alerts {n0}→{len(aws_hits)}")
            check("本地验签通过 → 证明对方在真实签名（不是 grep）",
                  aws_hits[-1]["evidence"].get("signature_valid") is True,
                  f"signature_valid={aws_hits[-1]['evidence'].get('signature_valid')} "
                  f"action={aws_hits[-1]['evidence'].get('action')}")
            check("返回的账号与实例一致（12 位，不复用 AWS 文档值）",
                  hp.oob.account in xml and len(hp.oob.account) == 12,
                  f"account={hp.oob.account}")

            # 篡改签名：仍然算命中（它确实在用这把钥匙），但必须标出验签失败
            body2 = b"Action=GetCallerIdentity&Version=2011-06-15&X=1"
            hdrs2 = sign_v4(akid, secret, host=host, body=body2)
            hdrs2.pop("Signature")
            hdrs2["Authorization"] = hdrs2["Authorization"][:-8] + "deadbeef"
            st2, _, _ = http_post(hp.http_port, "/sts", body2, hdrs2)
            last = [e for e in hp.oob.alerts() if e["kind"] == oob.KIND_AWS][-1]
            check("签名被篡改：仍告警但 signature_valid=False",
                  st2 == 200 and last["evidence"].get("signature_valid") is False,
                  f"status={st2} valid={last['evidence'].get('signature_valid')}")

            # 未知 key：必须 403，且不进告警
            n1 = len([e for e in hp.oob.alerts() if e["kind"] == oob.KIND_AWS])
            fake_akid, fake_secret = oob.gen_aws_key()
            hdrs3 = sign_v4(fake_akid, fake_secret, host=host, body=body)
            hdrs3.pop("Signature")
            st3, xml3, _ = http_post(hp.http_port, "/sts", body, hdrs3)
            n2 = len([e for e in hp.oob.alerts() if e["kind"] == oob.KIND_AWS])
            check("未签发的 key 返回 403 且不产生告警",
                  st3 == 403 and "InvalidClientTokenId" in xml3 and n2 == n1,
                  f"status={st3} alerts {n1}→{n2}")

            # -------------------------------------------------------------------
            print("\n=== 4. MCP token：tool-call-only ===")
            mh = {"Authorization": f"Bearer {mcp_tok}", "Content-Type": "application/json"}

            def rpc(method: str, params: dict | None = None, rid: int = 1):
                obj = {"jsonrpc": "2.0", "id": rid, "method": method}
                if params is not None:
                    obj["params"] = params
                return http_post(hp.http_port, "/mcp", json.dumps(obj).encode(), mh)

            n_touch = len([e for e in hp.oob.events if e["kind"] == oob.KIND_MCP
                           and e["severity"] == oob.SEV_TOUCH])
            n_alert = len([e for e in hp.oob.alerts() if e["kind"] == oob.KIND_MCP])

            def mcp_alerts() -> int:
                return len([e for e in hp.oob.alerts() if e["kind"] == oob.KIND_MCP])

            st_i, body_i, _ = rpc("initialize", {"protocolVersion": oob.McpSink.PROTOCOL,
                                                 "clientInfo": {"name": "Cursor", "version": "0.48.7"}})
            init = json.loads(body_i)
            check("initialize 返回协议版本与 serverInfo",
                  st_i == 200 and init["result"]["serverInfo"]["name"] == "archiver-mcp",
                  f"protocol={init['result']['protocolVersion']}")
            check("initialize 只算 touch，不算告警", mcp_alerts() == n_alert,
                  f"mcp alerts={mcp_alerts()}（touch 累计 {n_touch}→"
                  f"{len([e for e in hp.oob.events if e['kind'] == oob.KIND_MCP and e['severity'] == oob.SEV_TOUCH])}）")
            st_l, body_l, _ = rpc("tools/list", {}, 2)
            tools = json.loads(body_l)["result"]["tools"]
            check("tools/list 返回与世界一致的只读工具",
                  st_l == 200 and any(t["name"] == "archive.search" for t in tools),
                  f"{[t['name'] for t in tools]}")
            check("tools/list 仍不算告警", mcp_alerts() == n_alert)

            st_c, body_c, _ = rpc("tools/call", {"name": "archive.health", "arguments": {}}, 3)
            mcp_alerts_list = [e for e in hp.oob.alerts() if e["kind"] == oob.KIND_MCP]
            check("tools/call 触发唯一告警", st_c == 200 and mcp_alerts() == n_alert + 1,
                  f"status={st_c} mcp alerts={mcp_alerts()}")
            check("告警里带 tool 名与参数", mcp_alerts_list[-1]["evidence"].get("tool") == "archive.health",
                  f"tool={mcp_alerts_list[-1]['evidence'].get('tool')}")
            harness = hp.mcp.harness[-1] if hp.mcp.harness else {}
            check("顺手拿到 harness 指纹（clientInfo）", harness.get("name") == "Cursor",
                  f"{harness.get('name')} {harness.get('version')}")

            # 去重：60s 内同 token 同源重复触发不能把预算打爆
            n_before_dup = len(hp.oob.alerts())
            rpc("tools/call", {"name": "archive.health", "arguments": {}}, 4)
            check("同 token 60s 内重复触发被去重（不进预算分子）",
                  len(hp.oob.alerts()) == n_before_dup and hp.oob.counts["dup_suppressed"] >= 1,
                  f"dup_suppressed={hp.oob.counts['dup_suppressed']}")

            st_u, body_u, _ = http_post(hp.http_port, "/mcp",
                                        b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
                                        {"Content-Type": "application/json"})
            check("无 token 的 MCP 请求 401（不可当匿名工具面）", st_u == 401,
                  f"status={st_u} {body_u[:40]}")

            # -------------------------------------------------------------------
            print("\n=== 5. 红线：全程零出站 ===")
            kinds = hp.oob.by_kind()
            check("三类 token 各至少命中一次", all(kinds.get(k, 0) >= 1 for k in oob.OOB_KINDS),
                  f"{kinds}")
            check("账本里三条 ctype 齐全（dns/aws/mcp）",
                  {"dns", "aws", "mcp"} <= {e.get("ctype") for e in hp.ledger.events
                                            if e.get("kind") == "canary"},
                  f"canary 事件 {sum(1 for e in hp.ledger.events if e.get('kind') == 'canary')} 条")

            # 回放层必须吃得下新事件形状：带外事件的证据字段直接摊在事件上，
            # 没有 /c/ 那种 args dict。这里真跑一遍归因链，防止 UI 侧被新 ctype 打挂。
            import honey_replay
            sid = hp.sessions.by_key.get("127.0.0.1", "")
            mine = [e for e in hp.ledger.events if e.get("session") == sid]
            n_oob = sum(1 for e in mine if e.get("kind") == "canary"
                        and e.get("ctype") in oob.OOB_KINDS)
            chain = honey_replay.attribution_chain(mine)
            check("回放层能吃下带外 canary 事件（归因链不崩、步骤照旧）",
                  n_oob >= 3 and "steps" in chain and len(chain["steps"]) >= 2,
                  f"带外 canary {n_oob} 条 → steps={len(chain['steps'])} links={len(chain['links'])}")
        finally:
            hp.stop()

    check("NoEgressGuard：出站尝试 = 0", guard.clean,
          f"attempts={len(guard.attempts)} {guard.attempts[:2]}")

    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "honey_oob.py"),
               encoding="utf-8").read()
    # 只看「会真的发包」的原语；文档里提到 boto3 不算
    forbidden = ["urlopen(", "urllib.request", "http.client", "import boto3", "boto3.",
                 "botocore.", "import requests", "requests.get", "requests.post",
                 "smtplib.", "ftplib.", "paramiko.", "telnetlib."]
    found = [f for f in forbidden if f in src]
    check("静态检查：honey_oob.py 没有出站原语/云 SDK", not found,
          "无 urlopen/http.client/boto3/requests/…" if not found else f"发现 {found}")

    ok = all(results)
    print(f"\n{'=' * 62}\n{'PASS' if ok else 'FAIL'}  {sum(results)}/{len(results)} 项通过")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

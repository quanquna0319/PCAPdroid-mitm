#
#  This file is part of PCAPdroid.
#
#  PCAPdroid is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  PCAPdroid is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
#

"""
MagicBox 会员改写 —— 内置 mitmproxy addon
==========================================

与 js_injector.py 采用相同的内置方式：编译进 APK，启动时无条件加载，
不需要用户放置脚本、选择目录、授予文件权限或手动启用。

工作原理
--------
魔盒的会员查询接口是明文 HTTP：
    http://app.magicboxpro.org/ServerV110?fn=svv      （官方版）
    http://card.499713376.xyz/ServerV110?fn=svv       （域名破解版）

App 侧 MemberUtils$1$1 读取响应里的 err/et/iv/st/nv/pm/sa，
**没有任何签名或完整性校验**，直接拼成
    "imei#iv#et#st#nv#pm#sa"
交给 Des3Utils.b() 加密后写入 .member_new。
所以改写响应即可改写会员状态。

字段约束（全部来自 smali 逆向，缺一不可）
----------------------------------------
err  String  必须空串；非空则 App 整段跳过不处理
iv   int     必须 == 1；Splash.j() 里 MemberInfo.f() 返回该字段，
             只有等于 1 才把会员态置为 true
et   long    到期时间，给到 2099 即可
st   long    必须 ≈ 当前时间。原因：MemberUtils.b() 落盘后，
             读取时用 yyyyMMddHH（iv != 0 时）比对
             「文件 lastModified」与「st」，对不上就调 c() 重新拉取，
             会员不生效。因此 st 必须每次响应现取，不能缓存。
nv   int     版本标记
pm   int     权限位图
sa   int     激活标记，App 内转为 boolean

明文 HTTP 为何也能被处理
------------------------
PCAPdroid 的 should_proxify()（app/src/main/jni/core/capture_vpn.c:373）
对通过解密白名单的连接代理**全部 TCP**，源码注释原文：
  "Since we cannot reliably determine TLS connections with 1 packet, and
   connections must be proxified on the 1st packet, we proxify all the
   TCP connections"
白名单只按 IP / UID / 域名匹配，没有端口限制。所以 80 端口的明文 HTTP
同样进入 mitmproxy，response 钩子照常触发。
"""

import json
import time

from mitmproxy import ctx

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

# 会员到期时间（Unix 秒），2099-12-31 23:59:59
EXPIRE_TS = 4102415999

# 会员类型，必须 1
MEMBER_TYPE = 1

# 权限位图，全开
PERMISSION = 0x7FFFFFFF

NV = 1
SA = 1

# 需要处理的域名（官方版 + 域名破解版）
TARGET_HOSTS = {
    "app.magicboxpro.org",
    "card.499713376.xyz",
}

# 会员接口路径特征
MEMBER_KEY = "fn=svv"


class MagicBoxMember:
    name = "MagicBox Member"

    def __init__(self):
        self.hits = 0
        self.rewrites = 0

    def log(self, msg):
        try:
            ctx.log.info(msg)
        except Exception:
            print(msg)

    def response(self, flow):
        try:
            host = flow.request.pretty_host or ""
        except Exception:
            return

        if host not in TARGET_HOSTS:
            return

        try:
            path = flow.request.path or ""
        except Exception:
            return

        self.hits += 1
        self.log("[MagicBox] 命中 %s %s" % (flow.request.method, flow.request.pretty_url))

        if MEMBER_KEY not in path:
            return

        if flow.response is None or flow.response.content is None:
            return

        try:
            raw = flow.response.get_text(strict=False)
        except Exception:
            return

        self.log("[MagicBox] 原响应: %s" % (raw[:300] if raw else "(空)"))

        try:
            data = json.loads(raw)
        except Exception:
            self.log("[MagicBox] 非 JSON，原样放行")
            return

        if not isinstance(data, dict):
            self.log("[MagicBox] JSON 非对象，原样放行")
            return

        fake = {
            "err": "",
            "et": EXPIRE_TS,
            "iv": MEMBER_TYPE,
            "st": int(time.time()),   # 必须现取
            "nv": NV,
            "pm": PERMISSION,
            "sa": SA,
        }

        if all(data.get(k) == v for k, v in fake.items()):
            self.log("[MagicBox] 已是目标值，跳过")
            return

        data.update(fake)
        new_text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))

        try:
            flow.response.set_text(new_text)
        except Exception as e:
            self.log("[MagicBox] 写回失败: %s" % e)
            return

        # 这两个头和改写后的长度语义冲突，去掉
        for h in ("transfer-encoding", "content-encoding"):
            if h in flow.response.headers:
                del flow.response.headers[h]

        self.rewrites += 1
        self.log("[MagicBox] 已改写: %s" % new_text[:300])

    def done(self):
        self.log("[MagicBox] 卸载，共命中 %d 次、改写 %d 次"
                 % (self.hits, self.rewrites))

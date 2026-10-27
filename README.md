# cyber-radar · 全球网络安全态势雷达

> 每日自动聚合公开威胁情报，生成一份"今天全球网络世界发生了什么"的快照。
> 线上看板：<https://principia-rain.github.io/cyber-radar/>

## 这是什么

一个零依赖、纯聚合的安全态势看板：GitHub Actions 每天定时抓取 6 个公开情报源，
生成 `data/latest.json`（当日快照）、`data/history.json`（每日一个聚合点，最多 365 天）
和 `reports/日期.md`（中文日报），并用一个单文件静态页面展示。

**法律与安全边界：本项目只"读"公开数据源，不向任何第三方主机发包探测。**
主动扫描全球网络属于未授权探测（刑法 285/286 红线），被动聚合公开威胁情报
（OSINT / Threat Intelligence）才是安全研究的正路。

## 数据源（全部公开、免费、无需 API Key）

| 情报源 | 内容 | 回答的问题 |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已被在野利用的漏洞目录 | 攻击者真的在打哪些洞 |
| [NVD](https://nvd.nist.gov/) | 最近 7 天新披露 CVE | 新增攻击面有多少 |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | 当前活跃银行木马 C2 | 僵尸网络规模与家族 |
| [URLhaus](https://urlhaus.abuse.ch/) | 恶意软件分发 URL | 投毒与分发活动 |
| [SANS ISC](https://isc.sans.edu/) infocon | 全球威胁等级（绿~红） | 总体态势 |
| [SANS ISC](https://isc.sans.edu/) / DShield | 被攻击最多的端口 | 全球扫描压力 |

## 如何运行

- **自动**：GitHub Actions 每日 02:30 UTC（北京 10:30 左右，Actions 调度可能有 0–1 小时延迟）
  运行 `scripts/collect.py` 并自动提交数据。
- **手动**：仓库 Actions 页 → `daily-collect` → `Run workflow`。
- **本地**：`python scripts/collect.py`（仅标准库，无需安装任何包）。
- **本地预览页面**：`python -m http.server 8080` 后访问 <http://localhost:8080>
  （直接双击 index.html 打开会因 fetch 受限看不到数据）。

## 目录结构

```
scripts/collect.py            采集器（Python 标准库实现，单源失败不影响整体）
index.html                    看板（零依赖单文件，纯静态）
data/latest.json              当日快照
data/history.json             历史序列（最多 365 天）
reports/                      每日中文日报
.github/workflows/daily.yml   定时采集工作流
```

## 想加数据源？

在 `scripts/collect.py` 的 `SOURCES` 字典里加一项即可：键名、中文标签、
一个返回 dict 的函数。采集器会自动把失败降级为错误标记，不拖垮整体。
可选进阶（需要免费 API Key）：AlienVault OTX（社区威胁情报）、Cloudflare Radar（互联网流量异常）。

## License

MIT

# CLIProxyAPI Business Edition

[English](README.md) | 中文

本项目是 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的商业版本，面向企业级使用场景。

## 数据库连接说明

服务启动时会从以下位置读取数据库连接串（DSN）并自动执行迁移：

1. 优先使用 `DB_CONNECTION` 环境变量。
2. 若未设置环境变量，则读取 `config.yaml` 中的 `database-dsn` 或 `database.dsn` 字段。

> 注意事项：
>
> - DSN 必须包含 `postgres://` 或 `postgresql://` 前缀，以便正确识别为 PostgreSQL。
> - 若平台要求 SSL，请在 DSN 中追加 `sslmode=require`（或平台指定参数）。

## 贡献

提交合并请求（Pull Request）即表示您同意签署《贡献者许可协议》（CLA）。

所有贡献者在贡献内容被合并前，均需签署 CLA。该流程自动执行，耗时不到一分钟。

## 许可证

本项目采用 SSPL 许可证，详情见 [LICENSE](LICENSE) 文件。

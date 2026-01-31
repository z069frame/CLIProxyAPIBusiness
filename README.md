# CLIProxyAPI Business Edition

English | [中文](README_CN.md)

This is the Business version of [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI), it's designed for enterprise use.

## Database connection

The service loads the database DSN in this order and runs migrations on startup:

1. Prefer the `DB_CONNECTION` environment variable.
2. Otherwise read `database-dsn` or `database.dsn` from `config.yaml`.

> Notes:
>
> - The DSN must include a `postgres://` or `postgresql://` prefix to be recognized as PostgreSQL.
> - If the platform requires SSL, append `sslmode=require` (or the platform-specified parameter) to the DSN.

## Contributing

By submitting a pull request, you agree to sign the Contributor License Agreement (CLA).

All contributors are required to sign the CLA before their contributions can be merged. The process is automatic and takes less than one minute.

## License

This project is licensed under the SSPL License - see the [LICENSE](LICENSE) file for details.

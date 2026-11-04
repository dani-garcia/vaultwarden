> **语言**：本文档为简体中文翻译，[点此查看英文原版 README.md](README.md)。

![Vaultwarden Logo](./resources/vaultwarden-logo-auto.svg)

Bitwarden Client API 的另一个服务器实现，使用 Rust 编写，兼容[官方 Bitwarden 客户端](https://bitwarden.com/download/) [[免责声明](#disclaimer)]，非常适合那些运行资源繁重的官方服务并不理想的自托管部署场景。

---

[![GitHub Release](https://img.shields.io/github/release/dani-garcia/vaultwarden.svg?style=for-the-badge&logo=vaultwarden&color=005AA4)](https://github.com/dani-garcia/vaultwarden/releases/latest)
[![ghcr.io Pulls](https://img.shields.io/badge/dynamic/json?style=for-the-badge&logo=github&logoColor=fff&color=005AA4&url=https%3A%2F%2Fipitio.github.io%2Fbackage%2Fdani-garcia%2Fvaultwarden%2Fvaultwarden.json&query=%24.downloads&label=ghcr.io%20pulls&cacheSeconds=14400)](https://github.com/dani-garcia/vaultwarden/pkgs/container/vaultwarden)
[![Docker Pulls](https://img.shields.io/docker/pulls/vaultwarden/server.svg?style=for-the-badge&logo=docker&logoColor=fff&color=005AA4&label=docker.io%20pulls)](https://hub.docker.com/r/vaultwarden/server)
[![Quay.io](https://img.shields.io/badge/quay.io-download-005AA4?style=for-the-badge&logo=redhat&cacheSeconds=14400)](https://quay.io/repository/vaultwarden/server) <br>
[![Contributors](https://img.shields.io/github/contributors-anon/dani-garcia/vaultwarden.svg?style=flat-square&logo=vaultwarden&color=005AA4)](https://github.com/dani-garcia/vaultwarden/graphs/contributors)
[![Forks](https://img.shields.io/github/forks/dani-garcia/vaultwarden.svg?style=flat-square&logo=github&logoColor=fff&color=005AA4)](https://github.com/dani-garcia/vaultwarden/network/members)
[![Stars](https://img.shields.io/github/stars/dani-garcia/vaultwarden.svg?style=flat-square&logo=github&logoColor=fff&color=005AA4)](https://github.com/dani-garcia/vaultwarden/stargazers)
[![Issues Open](https://img.shields.io/github/issues/dani-garcia/vaultwarden.svg?style=flat-square&logo=github&logoColor=fff&color=005AA4&cacheSeconds=300)](https://github.com/dani-garcia/vaultwarden/issues)
[![Issues Closed](https://img.shields.io/github/issues-closed/dani-garcia/vaultwarden.svg?style=flat-square&logo=github&logoColor=fff&color=005AA4&cacheSeconds=300)](https://github.com/dani-garcia/vaultwarden/issues?q=is%3Aissue+is%3Aclosed)
[![AGPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/vaultwarden.svg?style=flat-square&logo=vaultwarden&color=944000&cacheSeconds=14400)](https://github.com/dani-garcia/vaultwarden/blob/main/LICENSE.txt) <br>
[![Dependency Status](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fdeps.rs%2Frepo%2Fgithub%2Fdani-garcia%2Fvaultwarden%2Fstatus.svg&query=%2F*%5Blocal-name()%3D'svg'%5D%2F*%5Blocal-name()%3D'g'%5D%5B2%5D%2F*%5Blocal-name()%3D'text'%5D%5B4%5D&style=flat-square&logo=rust&label=dependencies&color=005AA4)](https://deps.rs/repo/github/dani-garcia/vaultwarden)
[![GHA Release](https://img.shields.io/github/actions/workflow/status/dani-garcia/vaultwarden/release.yml?style=flat-square&logo=github&logoColor=fff&label=Release%20Workflow)](https://github.com/dani-garcia/vaultwarden/actions/workflows/release.yml)
[![GHA Build](https://img.shields.io/github/actions/workflow/status/dani-garcia/vaultwarden/build.yml?style=flat-square&logo=github&logoColor=fff&label=Build%20Workflow)](https://github.com/dani-garcia/vaultwarden/actions/workflows/build.yml) <br>
[![Matrix Chat](https://img.shields.io/matrix/vaultwarden:matrix.org.svg?style=flat-square&logo=matrix&logoColor=fff&color=953B00&cacheSeconds=14400)](https://matrix.to/#/#vaultwarden:matrix.org)
[![GitHub Discussions](https://img.shields.io/github/discussions/dani-garcia/vaultwarden?style=flat-square&logo=github&logoColor=fff&color=953B00&cacheSeconds=300)](https://github.com/dani-garcia/vaultwarden/discussions)
[![Discourse Discussions](https://img.shields.io/discourse/topics?server=https%3A%2F%2Fvaultwarden.discourse.group%2F&style=flat-square&logo=discourse&color=953B00)](https://vaultwarden.discourse.group/)

> [!IMPORTANT]
> **使用本服务器时，请直接向我们报告任何缺陷或建议（见[获取支持](#get-in-touch)），无论你使用的是哪种客户端（移动端、桌面端、浏览器……）。请勿使用官方的 Bitwarden 支持渠道。**

<br>

## 功能特性

它提供了 Bitwarden Client API 近乎完整的实现，包括：

 * [个人保险库（Personal Vault）](https://bitwarden.com/help/managing-items/)
 * [Send](https://bitwarden.com/help/about-send/)
 * [附件（Attachments）](https://bitwarden.com/help/attachments/)
 * [网站图标（Website icons）](https://bitwarden.com/help/website-icons/)
 * [个人 API 密钥（Personal API Key）](https://bitwarden.com/help/personal-api-key/)
 * [组织（Organizations）](https://bitwarden.com/help/getting-started-organizations/)
   - [集合（Collections）](https://bitwarden.com/help/about-collections/)、
     [密码共享（Password Sharing）](https://bitwarden.com/help/sharing/)、
     [成员角色（Member Roles）](https://bitwarden.com/help/user-types-access-control/)、
     [分组（Groups）](https://bitwarden.com/help/about-groups/)、
     [事件日志（Event Logs）](https://bitwarden.com/help/event-logs/)、
     [管理员密码重置（Admin Password Reset）](https://bitwarden.com/help/admin-reset/)、
     [目录连接器（Directory Connector）](https://bitwarden.com/help/directory-sync/)、
     [策略（Policies）](https://bitwarden.com/help/policies/)
 * [多重/双因素认证（Multi/Two Factor Authentication）](https://bitwarden.com/help/bitwarden-field-guide-two-step-login/)
   - [验证器应用（Authenticator）](https://bitwarden.com/help/setup-two-step-login-authenticator/)、
     [电子邮件（Email）](https://bitwarden.com/help/setup-two-step-login-email/)、
     [FIDO2 WebAuthn](https://bitwarden.com/help/setup-two-step-login-fido/)、
     [YubiKey](https://bitwarden.com/help/setup-two-step-login-yubikey/)、
     [Duo](https://bitwarden.com/help/setup-two-step-login-duo/)
 * [紧急访问（Emergency Access）](https://bitwarden.com/help/emergency-access/)
 * [Vaultwarden 管理后台（Admin Backend）](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page)
 * [改造过的 Web Vault 客户端](https://github.com/dani-garcia/bw_web_builds)（已内置在我们的容器中）

<br>

## 使用方法

> [!IMPORTANT]
> web-vault 要求使用 HTTPS 以及安全上下文来启用 [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)。 <br>
> 这意味着只有在你[启用 HTTPS](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS)后它才能工作。 <br>
> 我们还建议你使用[反向代理](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples)。

安装和使用 Vaultwarden 的推荐方式是通过我们发布在 [ghcr.io](https://github.com/dani-garcia/vaultwarden/pkgs/container/vaultwarden)、[docker.io](https://hub.docker.com/r/vaultwarden/server) 和 [quay.io](https://quay.io/repository/vaultwarden/server) 上的容器镜像。
关于所提供标签的说明，请参阅[该使用哪个容器镜像](https://github.com/dani-garcia/vaultwarden/wiki/Which-container-image-to-use)。

还有一些[社区维护的软件包](https://github.com/dani-garcia/vaultwarden/wiki/Third-party-packages)可供使用，但它们可能落后于最新版本，也可能在以何种方式配置 Vaultwarden 上有所偏离，详情见我们的 [Wiki](https://github.com/dani-garcia/vaultwarden/wiki)。

或者，你也可以自行[构建 Vaultwarden](https://github.com/dani-garcia/vaultwarden/wiki/Building-binary)。

Vaultwarden 基于 [Rocket web 框架](https://rocket.rs)，该框架内置了对 TLS 的支持，但我们的建议是你配置一个反向代理（见[代理示例](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples)）。

> [!TIP]
> **想要了解更多关于如何安装、使用和配置 Vaultwarden 的示例，请查阅我们的 [Wiki](https://github.com/dani-garcia/vaultwarden/wiki)。**

### Docker/Podman CLI

拉取容器镜像，并为持久化存储挂载一个来自主机的卷。<br>
如果你更倾向于使用 podman，可以把 `docker` 替换成 `podman`。

```shell
docker pull vaultwarden/server:latest
docker run --detach --name vaultwarden \
  --env DOMAIN="https://vw.domain.tld" \
  --volume /vw-data/:/data/ \
  --restart unless-stopped \
  --publish 127.0.0.1:8000:80 \
  vaultwarden/server:latest
```

这会将所有持久化数据保留在 `/vw-data/` 下，你可以根据需要调整该路径。

### Docker Compose

要使用 Docker compose，你需要创建一个 `compose.yaml`，用于承载运行 Vaultwarden 容器的配置。

```yaml
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: unless-stopped
    environment:
      DOMAIN: "https://vw.domain.tld"
    volumes:
      - ./vw-data/:/data/
    ports:
      - 127.0.0.1:8000:80
```

<br>

<a name="get-in-touch"></a>

## 获取支持

有问题、有建议，还是需要帮助？来加入我们在 [Matrix](https://matrix.to/#/#vaultwarden:matrix.org)、[GitHub Discussions](https://github.com/dani-garcia/vaultwarden/discussions) 或 [Discourse 论坛](https://vaultwarden.discourse.group/) 上的社区。

遇到了缺陷或崩溃？请搜索我们的议题跟踪器和讨论区，看看是否已有人报告。如果没有，请[发起一个新的讨论](https://github.com/dani-garcia/vaultwarden/discussions)或[创建一个新的议题](https://github.com/dani-garcia/vaultwarden/issues/)。请确认你使用的是 Vaultwarden 的最新版，并且没有类似的开放或已关闭议题！

<br>

## 贡献者

感谢你对本项目的贡献！

[![Contributors Count](https://img.shields.io/github/contributors-anon/dani-garcia/vaultwarden?style=for-the-badge&logo=vaultwarden&color=005AA4)](https://github.com/dani-garcia/vaultwarden/graphs/contributors)<br>
[![Contributors Avatars](https://contributors-img.web.app/image?repo=dani-garcia/vaultwarden)](https://github.com/dani-garcia/vaultwarden/graphs/contributors)

<br>

<a name="disclaimer"></a>

## 免责声明

**本项目与 [Bitwarden](https://bitwarden.com/) 或 Bitwarden, Inc. 并无关联。**

不过，Vaultwarden 的一位活跃维护者受雇于 Bitwarden，并被允许利用自己的个人时间为本项目做出贡献。这些贡献独立于 Bitwarden，并由其他维护者进行评审。

维护者们共同协作来为项目设定方向，专注于服务自托管社区——包括个人、家庭以及小型组织——同时确保项目的可持续性。

**请注意：** 对于使用 Vaultwarden 期间可能发生的任何数据丢失，我们无法承担责任。这包括由该应用处理的密码、附件及其他信息。我们强烈建议你定期备份自己的文件和数据库。但倘若你遭遇了数据丢失，我们鼓励你立即与我们联系。

<br>

## Bitwarden_RS

本项目曾名为 Bitwarden_RS，后更名为 Vaultwarden，以期将自己与官方的 Bitwarden 服务器区分开来，从而避免混淆以及商标/品牌方面的问题。<br>
更多说明请参阅 [#1642 - v1.21.0 版本发布及项目更名为 Vaultwarden](https://github.com/dani-garcia/vaultwarden/discussions/1642)。

This fork of the NATS server was planned to promote my UDS patches to NATS. It looks like the scope of the changes is not acceptable by upstream.

I need these changes for a project of mine and keep the fork around in case NATS will reconsider adding them later on. However, due to my time constraints
I probably can't keep up syncing changes, so there is a good chance this becomes a hard fork in the future.

If you are interested in or need these changes and require robust support, I am - in principle - available for hire.

The project I am working on is "System NATS" or snats. That's the working title. It's an embedded NATS server based on this fork that operates as a
system bus for Linux nodes (similar to DBUS) integrating into a communication mesh. This in turn is part of the onpremix project, a site/organization/network/fleet management solution for on-premise deployments,
e.g. home labs, small business infrastructure or alternative cloud/edge solutions. Both of these projects will be open source projects when they reach
a sufficient maturity level. They are not yet public though.

So while I am actively using this fork and maintain it for my use cases, it's not really supported in its current form.

## Changes in this fork

Full documentation is in the [wiki](https://github.com/mutech/nats-server/wiki):

- **UNIX domain sockets** (*implemented*) — a UDS transport for the server, with
  peer-credential (uid/gid/pid) authentication. See
  [UNIX domain sockets](https://github.com/mutech/nats-server/wiki/UNIX-domain-sockets)
  and the [UDS permission model](https://github.com/mutech/nats-server/wiki/UDS-Permission-Model).
- **`file://` nkey references** (*implemented*) — any nkey or seed in the config
  may be a `file://` URL, read at runtime, so secrets stay out of the config
  file. See [NKey file references](https://github.com/mutech/nats-server/wiki/NKey-file-references).
- **Peer authorization** (*planned*) — propagate the publisher's identity to
  subscribers. See [Peer authorization](https://github.com/mutech/nats-server/wiki/Peer-authorization).

## Related projects

The UDS transport needs a client that can dial a Unix socket. These companion
forks add that:

- [natscli](https://github.com/mutech/natscli) — the `nats` CLI, with a
  `nats+uds://` URL scheme for UDS connections.
- [nats.py](https://github.com/mutech/nats.py) — Python client with UDS support.
- [nats.zig](https://github.com/mutech/nats.zig) — Zig client with UDS support.

Programmatic Go clients need no fork — set a custom dialer
(`nats.SetCustomDialer`) that dials `unix`.

# Original Upstream README

<p align="center">
  <img src="logos/nats-horizontal-color.png" width="300" alt="NATS Logo">
</p>

[NATS](https://nats.io) is a simple, secure and performant communications system for digital systems, services and devices. NATS is part of the Cloud Native Computing Foundation ([CNCF](https://cncf.io)). NATS has over [40 client language implementations](https://nats.io/download/), and its server can run on-premise, in the cloud, at the edge, and even on a Raspberry Pi. NATS can secure and simplify design and operation of modern distributed systems.

[![License][License-Image]][License-Url] [![Build][Build-Status-Image]][Build-Status-Url] [![Release][Release-Image]][Release-Url] [![Slack][Slack-Image]][Slack-Url] [![Coverage][Coverage-Image]][Coverage-Url] [![Docker Downloads][Docker-Image]][Docker-Url] [![GitHub Downloads][GitHub-Image]][Somsubhra-URL] [![CII Best Practices][CIIBestPractices-Image]][CIIBestPractices-Url] [![Artifact Hub][ArtifactHub-Image]][ArtifactHub-Url]

## Documentation

- [Official Website](https://nats.io)
- [Official Documentation](https://docs.nats.io)
- [FAQ](https://docs.nats.io/reference/faq)
- Watch [a video overview](https://rethink.synadia.com/episodes/1/) of NATS.
- Watch [this video from SCALE 13x](https://www.youtube.com/watch?v=sm63oAVPqAM) to learn more about its origin story and design philosophy.

## Contact

- [Twitter](https://twitter.com/nats_io): Follow us on Twitter!
- [Google Groups](https://groups.google.com/forum/#!forum/natsio): Where you can ask questions
- [Slack](https://natsio.slack.com): Click [here](https://slack.nats.io) to join. You can ask questions to our maintainers and to the rich and active community.

## Contributing

If you are interested in contributing to NATS, read about our...

- [Contributing guide](./CONTRIBUTING.md)
- [Report issues or propose Pull Requests](https://github.com/nats-io)

[License-Url]: https://www.apache.org/licenses/LICENSE-2.0
[License-Image]: https://img.shields.io/badge/License-Apache2-blue.svg
[Docker-Image]: https://img.shields.io/docker/pulls/_/nats.svg
[Docker-Url]: https://hub.docker.com/_/nats
[Slack-Image]: https://img.shields.io/badge/chat-on%20slack-green
[Slack-Url]: https://slack.nats.io
[Fossa-Url]: https://app.fossa.io/projects/git%2Bgithub.com%2Fnats-io%2Fnats-server?ref=badge_shield
[Fossa-Image]: https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnats-io%2Fnats-server.svg?type=shield
[Build-Status-Url]: https://github.com/nats-io/nats-server/actions/workflows/tests.yaml
[Build-Status-Image]: https://github.com/nats-io/nats-server/actions/workflows/tests.yaml/badge.svg?branch=main
[Release-Url]: https://github.com/nats-io/nats-server/releases/latest
[Release-Image]: https://img.shields.io/github/v/release/nats-io/nats-server
[Coverage-Url]: https://coveralls.io/r/nats-io/nats-server?branch=main
[Coverage-image]: https://coveralls.io/repos/github/nats-io/nats-server/badge.svg?branch=main
[ReportCard-Url]: https://goreportcard.com/report/nats-io/nats-server
[ReportCard-Image]: https://goreportcard.com/badge/github.com/nats-io/nats-server
[CIIBestPractices-Url]: https://bestpractices.coreinfrastructure.org/projects/1895
[CIIBestPractices-Image]: https://bestpractices.coreinfrastructure.org/projects/1895/badge
[ArtifactHub-Url]: https://artifacthub.io/packages/helm/nats/nats
[ArtifactHub-Image]: https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nats
[GitHub-Release]: https://github.com/nats-io/nats-server/releases/
[GitHub-Image]: https://img.shields.io/github/downloads/nats-io/nats-server/total.svg?logo=github
[Somsubhra-url]: https://somsubhra.github.io/github-release-stats/?username=nats-io&repository=nats-server

## Roadmap

The NATS product roadmap can be found [here](https://nats.io/about/#roadmap).

## Adopters

Who uses NATS? See our [list of users](https://nats.io/#who-uses-nats) on [https://nats.io](https://nats.io).

## Security

### Security Audit

A third party security audit was performed by Trail of Bits following engagement by the Open Source Technology Improvement Fund (OSTIF). You can see the [full report from April 2025 here](https://github.com/trailofbits/publications/blob/master/reviews/2025-04-ostif-nats-securityreview.pdf).

### Reporting Security Vulnerabilities

If you've found a vulnerability or a potential vulnerability in the NATS server, please let us know at
[nats-security](mailto:security@nats.io).

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.

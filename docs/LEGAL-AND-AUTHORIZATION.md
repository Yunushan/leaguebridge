# Legal and authorization gates

LeagueBridge's project-authored source and metadata use the 0BSD license. The
release executable also contains exactly one approved external Go module,
`filippo.io/edwards25519` v1.2.0, under the BSD-3-Clause license. Its source is
committed under `vendor/`, its upstream license remains in that tree, and the
full binary-redistribution notice is appended to the root `LICENSE` shipped in
every archive. Additional vendored modules support repository schema tests and
are not compiled into the release executable. LeagueBridge does not ship Riot
Client, League of Legends, Vanguard, Riot assets, Windows media, proprietary
DLLs, Moonlight, or Sunshine.

Except for the disclosed vendored Go modules, users obtain third-party software
from its publisher and remain responsible for its terms and licenses. A Windows
installation needs a valid license; setup keys used by automation projects are
not activation licenses.

Riot Developer Portal registration or product review is not, by itself,
authorization to port, emulate, bypass, or redistribute Vanguard. Any future
local runtime needs official support or express written authorization covering
the exact platform, anti-cheat behavior, test method, and distribution scope.

Relevant current policies:

- [Riot Terms of Service](https://www.riotgames.com/en/terms-of-service-update-2024)
- [Riot Developer General Policies](https://developer.riotgames.com/policies/general)
- [Riot Legal Jibber Jabber](https://www.riotgames.com/en/legal)
- [Riot security reporting](https://www.riotgames.com/en/reporting-a-security-vulnerability)

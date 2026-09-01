# wg-frag-go

[English](README.md)

`wg-frag-go`（WGF）は、`wireguard-go` を基盤とするユーザー空間の L3
フラグメント分割・パッキング shim です。WireGuard のハンドシェイク、Noise プロトコル、
暗号化、鍵更新、エンドポイント移動、リプレイ保護を変更せずに、下位ネットワークより
大きな内側 IP MTU を維持します。

```text
内側 IPv4/IPv6 パケット
        |
        v
WGF DATA record を carrier へパッキング
        |
        v
wireguard-go
        |
        v
暗号化された UDP/IP 下位ネットワーク
```

DATA 通信では両端で WGF を動かす必要があります。標準の WireGuard peer は下位の
WireGuard セッションを確立できますが、WGF carrier は交換できません。

## 機能

- 内側 MTU は1280〜9612 bytesで、1つの内側パケットを最大16 fragmentへ分割します。
- carrier packing、上限付きの reassembly / reorder queue、通常のホットパスでの
  メモリ確保なし。
- RFC 8899 を基にした実行時 DPLPMTUD。安全な613-byteの carrier payloadから開始し、
  経路に合わせて拡大します。
- WireGuard 互換の複数peer設定、`AllowedIPs` 選択と受信元検証、transport非依存の
  Go manager API、ローカル gRPC adapter、複数interface管理、systemd を提供します。

互換性の境界と状態機械の規則は [wire protocol](docs/protocol.md) を参照してください。

## 性能

WGF は設定した内側 MTU を維持しながら、定常状態の転送で GC 負荷を抑える設計です。4 vCPUの
リージョン間参照環境では、内側 MTU 1500〜9600 bytesで単一 TCP flow が約0.7 Gbps、
4並列 flow が約2.5〜2.8 Gbpsでした。これは性能保証ではなく参照測定です。測定方法、
完全な結果、ローカル検証は [benchmarks](docs/benchmark.md) を参照してください。

## 最短導入

WGF は Linux amd64 / arm64 と macOS amd64 / arm64 で動作します。Linux は `wgf run`、
`wgf manager`、`wgf quick` に対応し、macOS は `wgf run` と `wgf manager` に対応します。
interfaceの作成と route管理には root または同等の network 権限が必要です。

対応 Ubuntu release では Launchpad PPA から導入できます。

```sh
sudo add-apt-repository ppa:kurochan/wg-frag-go
sudo apt update
sudo apt install wg-frag-go
```

[`examples/wgf0.conf.example`](examples/wgf0.conf.example) を基に
`/etc/wgf/wgf0.conf` を作成し、mode `0600` にしてから検証・起動します。

```sh
sudo wgf check --config /etc/wgf/wgf0.conf
sudo systemctl enable --now wgf@wgf0
sudo wgf show wgf0
```

package は tunnel unit を自動で enable / start しません。GitHub Releases、導入方法、
設定、診断、upgradeの詳細は [Installation and operations](docs/install.md) を参照してください。

## ドキュメント

- [Installation and operations](docs/install.md): release package、PPA、起動、診断、
  AppArmor、upgrade。
- [Configuration reference](docs/configuration.md): interface、peer、WGF 固有設定の全項目。
- [Control API](docs/control-api.md): in-process Go API、public gRPC API、複数interface
  manager、lifecycle、mutationの規則。
- [Wire protocol](docs/protocol.md): carrier format、capability、PMTU、reassembly の仕様。
- [Security model](docs/threat-model.md): trust boundary、検証、残存リスク。
- [Benchmarks](docs/benchmark.md): 再現可能な Internet / Linux の測定結果。

## 開発

ビルドには Go 1.26.0 以降が必要です。通常の検証は特権 network 環境を必要としません。

```sh
make build
go test ./...
make lint
make test-race
```

特権が必要な Linux network namespace test と benchmark のコマンドは
[benchmarks](docs/benchmark.md) に記載しています。

## セキュリティ

WireGuard が暗号と peer 認証の境界です。WGF は TUN へパケットを渡す前に、carrier構造、
peer・session状態、リソース上限、内側パケットの送信元prefixを検証します。詳細は
[security model](docs/threat-model.md) を参照してください。

脆弱性は public issue ではなく [SECURITY.md](SECURITY.md) の手順で非公開報告してください。

## ライセンス

MIT Licenseで配布します。詳細は [LICENSE](LICENSE) を参照してください。

## プロジェクトの関係

wg-frag-go は WireGuard protocol と `wireguard-go` 実装を利用しますが、WireGuard
project とは無関係の独立した project です。WireGuard project の一部ではなく、同 project
から承認・推奨されたものでもありません。

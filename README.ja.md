# wg-frag-go

`wg-frag-go` は、`wireguard-go` を基盤とするユーザー空間の L3
フラグメント分割・パッキング shim です。WireGuard のハンドシェイク、Noise プロトコル、
暗号化、鍵更新、エンドポイント移動、リプレイ保護を変更せずに、下位ネットワークより
大きな内側 IP MTU を維持します。

shim はネイティブ L3 TUN と WireGuard の平文デバイスの間で動作します。

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

DATA 通信では両端で WGF を動かす必要があります。標準の WireGuard エンドポイントは
WireGuard セッション自体を確立できますが、WGF carrier は解釈できません。

## 機能

- 内側 MTU は1280〜9612 bytes（既定値: 1500）。
- 1つの内側パケットを最大16 fragmentへ分割。
- 異なる内側パケットの複数recordを1つの carrierへ格納。
- 固定長の reassembly queue と reorder queue によるメモリ上限。ホットパスで
  メモリ確保を行いません。
- WireGuard peerごとに決定的に生成する非公開の IPv6 carrier address。interface
  address、route、ユーザー設定の AllowedIP には公開しません。
- protobuf（edition 2024）による CONTROL carrier。capability交換、sequence reset、
  peer MTU交換、到達性確認、PMTU探索に使用します。
- RFC 8899 を基にした実行時 DPLPMTUD。DATA は613-byteのbase carrier payloadから
  開始し、probe成功後に拡大します。確認に失敗した場合はbaseへ戻り、backoffして
  再探索します。
- Linux の外側 UDP socket で IP fragmentation を禁止し、local `EMSGSIZE` を
  PMTU engineへ通知します。利用可能な環境では `recvmmsg`/`sendmmsg` と UDP
  GSO/GRO を使い、未対応の場合は自動的にフォールバックします。
- WireGuard 互換の複数peer設定、`AllowedIPs` の最長プレフィックス一致によるpeer選択、
  ingress source validation。
- `wgf` / `wgf-quick` CLI、interfaceごとの Unix control socket、gRPC control API、
  構造化 `slog` logging、systemd unit。

wire format と状態機械の規則は
[`docs/protocol.md`](docs/protocol.md) に記載しています。

## 動作要件

実行環境は Linux の amd64 と arm64 を対象とします。バイナリのビルドには Go 1.26.4
以降が必要です。interfaceの起動には通常、rootまたは TUN 作成、route/rule設定、
UDP socket mark設定、socket buffer要求に必要な権限が必要です。

## ビルドとインストール

```sh
make build
sudo install -m 0755 bin/wgf /usr/bin/wgf
sudo ln -sf wgf /usr/bin/wgf-quick
sudo install -d -m 0700 /etc/wg-frag
sudo install -m 0644 dist/systemd/wgf@.service dist/systemd/wgf.target \
  /usr/lib/systemd/system/
sudo systemctl daemon-reload
```

詳細な導入・運用手順は [`docs/install.md`](docs/install.md) を参照してください。

protobuf の生成には `tools/go.mod` でバージョンを固定したツールを使用します。

```sh
make proto
make proto-check
go tool -modfile=tools/go.mod buf lint
```

## 設定

設定ファイルは WireGuard と同じ形式の INI です。interfaceには address、秘密鍵、
1つ以上の peer を設定します。

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = <base64-private-key>
ListenPort = 51820
MTU = 1500

[Peer]
PublicKey = <base64-peer-public-key>
Endpoint = example.net:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
PresharedKey = <base64-preshared-key>
```

`MTU` は内側 TUN の MTU です。1280〜9612 bytes の範囲で指定し、現在の
carrier payloadを超えるパケットは WGF がfragmentします。WGF固有の設定で、base / 最大
carrier payload、PMTU探索、reassembly容量・有効期間、reorder、UDP socket bufferを
調整できます。受け付ける範囲とプロトコル上の制限はパーサーと
[`docs/protocol.md`](docs/protocol.md) を参照してください。

`PresharedKey` は任意の32バイトWireGuard preshared keyです。`wgf genpsk`で生成できます。

ユーザーが設定した `AllowedIPs` は送信時の peer選択と、reassembly後の受信
パケットの送信元検証に使います。WGFが内部管理する非公開の carrier addressを
ユーザー設定へ追加してはいけません。

## コマンド

```sh
wgf genkey | tee private.key | wgf pubkey
wgf genpsk
wgf check --config /etc/wg-frag/wgf0.conf

# フォアグラウンドデーモン
sudo wgf run wgf0 --config /etc/wg-frag/wgf0.conf

# wg-quick 互換のライフサイクル（wgf-quick は実行ファイル名によるalias）
sudo wgf quick up wgf0
sudo wgf quick down wgf0
sudo wgf quick save wgf0
sudo wgf quick strip wgf0

# systemd のライフサイクル
sudo systemctl enable --now wgf@wgf0
sudo systemctl stop wgf@wgf0

# 状態と設定
wgf show
wgf show wgf0
wgf show wgf0 path-mtu
wgf show wgf0 stats
wgf showconf wgf0
```

`wgf-quick` は `wgf quick` のaliasです。`wgf run` はinterfaceごとのフォアグラウンド
デーモンとして動作します。`wgf quick` はinterfaceを作成し、デーモンを起動し、address
とrouteを設定します。`Table = auto` は WireGuard 互換の full-tunnel policy
routing rule と endpoint route exemption を設定します。`Table = off` を指定すると
route管理を呼び出し元へ委ねます。

## ログと管理

デーモンは Go の `log/slog` で構造化ログを出力します。通常の INFO は起動、終了、設定変更、
転送状態の変更、PMTU変更に限定します。packet単位の失敗は個別にログ出力せず、
counterへ記録し、rate limitします。

診断時は環境変数で動作を調整できます。

- `WGF_LOG_LEVEL`: `debug`、`info`（既定）、`warn`、`error`、`silent`。
- `WGF_LOG_FORMAT`: `text`（既定）または `json`。
- `WGF_CPU_PROFILE`: デーモン実行中の Go CPU profile を指定パスへ出力します。
  通常運用では未設定にしてください。実行内容や負荷の情報が含まれる可能性があるため、
  出力ファイルの権限を保護してください。

これらは診断用の環境変数であり、設定ファイルの項目ではありません。

各interfaceは `/run/wg-frag/<interface>.sock` に mode 0600 の非公開
Unix socketを公開します。`wgf show`、`set`、`setconf`、`addconf`、`syncconf` は
このsocket上の gRPC `controlapi/v1` serviceを使います。socketはローカル専用で、
ネットワーク listenerではありません。

## プロトコルと動作

WGF DATA carrier と CONTROL carrier は混載しません。DATA recordは fragmentの
index/count、wire lane、16-bit data session、32-bit lane sequence、元パケット内の
offsetを含む12-byte headerを持ちます。carrier payloadには収まる限り完全なrecordを
格納し、record countは送信しません。

senderはTUN batchを `EAGAIN` までdrainし、partial carrierを直ちにflushします。
パッキング待ちtimerはありません。reassemblyはパケットの全fragmentが揃うまで待ち、reorder
は完成済みパケットに対して独立してlaneごとに適用します。reorder gapは設定された短い
遅延（既定10 ms）だけ保持し、その後はskipします。

native IPv4 fragment と IPv6 Fragment Header packet は拒否してcounterへ記録します。
WGFは内側パケットを再送しません。WireGuardが認証、機密性、outer replay protection
を提供し、WGFは復号後に carrier構造、peer identity、session state、sequence state、
ユーザー `AllowedIPs` を検証します。

## テスト

通常のテストスイート、lint、race testは特権Linux環境を必要としません。

```sh
go test ./...
make lint
make test-race
```

fuzz targetでは、設定パーサー、inner IPパーサー、carrier / CONTROLデコーダー、receiver
の入力処理を検証します。

```sh
make fuzz
FUZZTIME=5m make fuzz
```

特権が必要な Linux integration test は明示的に指定した場合だけ実行します。Goだけで
一時的な network namespace、veth、TUN、WireGuard peerを作成し、ホストのディレクトリを
mountせず、`ip`、`tc`、`tcpdump`も呼び出しません。

```sh
make test-netns
make test-netns-control-recovery
make test-netns-base-recovery
make test-netns-no-fragment
make bench-netns
```

再現可能な測定手順と保存しているLinuxの実測事実は
[`docs/benchmark.md`](docs/benchmark.md) にまとめています。

テストには Linux networking capability（通常は `CAP_NET_ADMIN` と `CAP_NET_RAW`）と
`/dev/net/tun` が必要です。fault injection variantは Makefile とtest nameに記載した
`WGF_NETNS_*` 環境変数で選択します。

## セキュリティモデル

WireGuardが暗号とpeer認証の境界です。WGFは認証済みpeerからの入力も不正形式である
可能性を前提にし、TUNへ渡す前に carrier length、record range、protobuf limit、session
遷移、reassembly上限、source prefixを検証します。詳細なtrust boundaryと運用上の前提は
[`docs/threat-model.md`](docs/threat-model.md) を参照してください。

## ライセンス

MIT Licenseで配布します。詳細は [`LICENSE`](LICENSE) を参照してください。

脆弱性の報告は無保証・ベストエフォートで対応します。機密情報をIssueへ公開せず、
[`SECURITY.md`](SECURITY.md) の非公開報告手順を利用してください。

## プロジェクトの関係

wg-frag-goはWireGuardプロトコルと`wireguard-go`実装を利用していますが、
WireGuardプロジェクトとは無関係の独立したプロジェクトです。WireGuardプロジェクトの
一部ではなく、同プロジェクトから承認・推奨されたものでもありません。

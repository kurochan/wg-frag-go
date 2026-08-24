#!/usr/bin/env ruby
# frozen_string_literal: true

# Verifies a macOS WGF peer against a Linux WGF peer booted by QEMU's TCG
# backend. The guest image is assembled in a temporary directory and no host
# directory is mounted into the guest.

require "digest"
require "fileutils"
require "open3"
require "socket"
require "tmpdir"

GUEST_ADDRESS = "10.254.91.2"
HOST_ADDRESS = "10.254.91.1"
TRANSFER_BYTES = 1024 * 1024
# Update this URL and all three checksums together with
# update-macos-qemu-e2e-artifacts.rb, then run this E2E test on macOS.
ALPINE_NETBOOT = "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot"
ALPINE_ARTIFACTS = {
  "vmlinuz-virt" => "1a2fa67cb25a2fa9065818712d50d0d543526818b3c6b43695e54deaca33d66d",
  "initramfs-virt" => "df5281b4c36f812d0507e219e31a8a7482e0b4175097e292b75c7872c441295c",
  "modloop-virt" => "83599ae8dbdd48ab452600c00bce8dd1c0c77075223196732cd99b7f8d774f89"
}.freeze
# These are the modules required by QEMU's default virtio NIC and WGF's TUN.
# Keep their dependency order when updating the Alpine kernel image.
GUEST_MODULES = [
  "kernel/net/core/failover.ko",
  "kernel/drivers/net/net_failover.ko",
  "kernel/drivers/net/virtio_net.ko",
  "kernel/drivers/net/tun.ko"
].freeze

def run!(*command, env: {}, **options)
  success = system(env, *command, **options)
  raise "command failed: #{command.join(" ")}" unless success
end

def command_path(name)
  path = ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).map do |directory|
    File.join(directory, name)
  end.find { |candidate| File.executable?(candidate) && !File.directory?(candidate) }
  raise "missing command: #{name}" unless path

  path
end

def wait_for(timeout:, interval: 0.1)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
  loop do
    return if yield
    raise "timed out after #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

    sleep interval
  end
end

def terminate(pid)
  return unless pid

  Process.kill("TERM", -pid)
  Process.wait(pid)
rescue Errno::ESRCH, Errno::ECHILD
  nil
end

def write_config(path, private_key:, listen_port:, public_key:, endpoint:, allowed_ip:)
  File.write(path, <<~CONFIG)
    [Interface]
    PrivateKey = #{private_key}
    ListenPort = #{listen_port}
    MTU = 1500

    [Peer]
    PublicKey = #{public_key}
    Endpoint = #{endpoint}
    AllowedIPs = #{allowed_ip}
    PersistentKeepalive = 1
  CONFIG
  File.chmod(0o600, path)
end

def guest_init
  <<~'SH'
    #!/bin/sh
    set -eu

    /bin/busybox mount -t proc proc /proc
    /bin/busybox mount -t sysfs sysfs /sys
    /bin/busybox mount -t devtmpfs devtmpfs /dev
    /bin/busybox mkdir -p /tmp /run /dev/net
    /bin/busybox mknod /dev/net/tun c 10 200 2>/dev/null || true
    /bin/busybox insmod /failover.ko
    /bin/busybox insmod /net_failover.ko
    /bin/busybox insmod /virtio_net.ko
    /bin/busybox ip link set eth0 up
    /bin/busybox ip addr add 10.0.2.15/24 dev eth0
    /bin/busybox ip route add default via 10.0.2.2
    /bin/busybox insmod /tun.ko

    /wgf run wgfguest --config /wgf.conf >/tmp/wgf.log 2>&1 &
    wgf_pid=$!
    for _ in $(/bin/busybox seq 1 60); do
      if [ -e /sys/class/net/wgfguest ]; then
        break
      fi
      /bin/busybox sleep 1
    done
    if [ ! -e /sys/class/net/wgfguest ]; then
      /bin/busybox cat /tmp/wgf.log >&2 || true
      exit 1
    fi
    /bin/busybox ip link set wgfguest up
    /bin/busybox ip addr add 10.254.91.2/32 dev wgfguest
    /bin/busybox ip route add 10.254.91.1/32 dev wgfguest

    receive() {
      /bin/busybox nc -l -p 19091 >/tmp/received
      bytes=$(/bin/busybox wc -c </tmp/received)
      digest=$(/bin/busybox sha256sum /tmp/received | /bin/busybox awk '{ print $1 }')
      echo "WGF_QEMU_RECEIVED $bytes $digest"
    }
    receive &
    echo WGF_QEMU_GUEST_READY
    wait "$wgf_pid"
  SH
end

root = Dir.mktmpdir("wgf-macos-qemu.", ENV.fetch("RUNNER_TEMP", "/tmp"))
host_pid = nil
qemu_pid = nil
host_utun = nil

begin
  run!("sudo", "-n", "true")
  qemu = command_path("qemu-system-aarch64")
  unsquashfs = command_path("unsquashfs")
  command_path("cpio")

  mac_binary = File.join(root, "wgf-macos")
  linux_binary = File.join(root, "wgf-linux")
  run!("go", "build", "-trimpath", "-o", mac_binary, "./cmd/wgf")
  run!("go", "build", "-trimpath", "-o", linux_binary, "./cmd/wgf",
       env: { "CGO_ENABLED" => "0", "GOOS" => "linux", "GOARCH" => "arm64" })

  private_a, = Open3.capture2(mac_binary, "genkey")
  private_b, = Open3.capture2(mac_binary, "genkey")
  public_a, = Open3.capture2(mac_binary, "pubkey", stdin_data: private_a)
  public_b, = Open3.capture2(mac_binary, "pubkey", stdin_data: private_b)
  [private_a, private_b, public_a, public_b].each(&:strip!)
  host_port = 40_000 + (Process.pid % 10_000)
  guest_port = host_port + 1

  host_config = File.join(root, "host.conf")
  write_config(host_config, private_key: private_a, listen_port: host_port, public_key: public_b,
               endpoint: "127.0.0.1:#{guest_port}", allowed_ip: "#{GUEST_ADDRESS}/32")

  ALPINE_ARTIFACTS.each do |artifact, digest|
    path = File.join(root, artifact)
    run!("curl", "--fail", "--location", "--retry", "3", "--output", path, "#{ALPINE_NETBOOT}/#{artifact}")
    raise "unexpected SHA-256 for #{artifact}" unless Digest::SHA256.file(path).hexdigest == digest
  end

  initrd = File.join(root, "initrd")
  FileUtils.mkdir_p(initrd)
  run!("sh", "-c", "gzip -dc \"$1\" | cpio -idmu --quiet", "sh", File.join(root, "initramfs-virt"), chdir: initrd)
  modloop_image = File.join(root, "modloop-virt")
  listing, status = Open3.capture2e(unsquashfs, "-ll", modloop_image)
  raise "could not inspect Alpine modloop" unless status.success?

  GUEST_MODULES.each_with_index do |suffix, index|
    entry = listing.each_line.map { |line| line.split.last }.find { |path| path&.end_with?("/#{suffix}") }
    raise "module not found in Alpine modloop: #{suffix}" unless entry

    entry = entry.delete_prefix("squashfs-root/")
    destination = File.join(root, "module-#{index}")
    run!(unsquashfs, "-d", destination, modloop_image, entry)
    FileUtils.cp(File.join(destination, entry), File.join(initrd, File.basename(suffix)))
  end

  FileUtils.cp(linux_binary, File.join(initrd, "wgf"))
  write_config(File.join(initrd, "wgf.conf"), private_key: private_b, listen_port: guest_port, public_key: public_a,
               endpoint: "10.0.2.2:#{host_port}", allowed_ip: "#{HOST_ADDRESS}/32")
  File.write(File.join(initrd, "init"), guest_init)
  FileUtils.chmod(0o755, [File.join(initrd, "init"), File.join(initrd, "wgf")])

  initramfs = File.join(root, "wgf-initramfs")
  run!("sh", "-c", "find . -print | cpio -o -H newc --quiet --owner=0:0 | gzip -n >\"$1\"", "sh", initramfs, chdir: initrd)

  host_log = File.join(root, "host.log")
  host_pid = Process.spawn("sudo", "-n", mac_binary, "run", "wgfmac0", "--config", host_config,
                           out: host_log, err: host_log, pgroup: true)
  wait_for(timeout: 10) do
    match = File.exist?(host_log) && File.read(host_log).match(/native_interface=(utun\d+)/)
    host_utun = match[1] if match
    host_utun
  end
  run!("sudo", "-n", "ifconfig", host_utun, "inet", HOST_ADDRESS, GUEST_ADDRESS, "netmask", "255.255.255.255", "up")
  system("sudo", "-n", "route", "-n", "add", "-host", GUEST_ADDRESS, "-interface", host_utun)

  qemu_log = File.join(root, "qemu.log")
  qemu_pid = Process.spawn(qemu, "-M", "virt", "-cpu", "cortex-a72", "-accel", "tcg", "-m", "768", "-nographic",
                           "-kernel", File.join(root, "vmlinuz-virt"), "-initrd", initramfs, "-append", "console=ttyAMA0",
                           "-nic", "user,hostfwd=udp:127.0.0.1:#{guest_port}-:#{guest_port}", out: qemu_log, err: qemu_log,
                           pgroup: true)
  wait_for(timeout: 30) { File.exist?(qemu_log) && File.binread(qemu_log).include?("WGF_QEMU_GUEST_READY") }

  wait_for(timeout: 20) { system("ping", "-q", "-c", "1", "-W", "1000", GUEST_ADDRESS, out: File::NULL, err: File::NULL) }
  run!("ping", "-q", "-c", "3", "-W", "1000", GUEST_ADDRESS)

  sent = File.join(root, "sent")
  File.binwrite(sent, "\0" * TRANSFER_BYTES)
  TCPSocket.open(GUEST_ADDRESS, 19_091) do |socket|
    File.open(sent, "rb") { |source| IO.copy_stream(source, socket) }
    socket.close_write
  end

  wait_for(timeout: 20) { File.exist?(qemu_log) && File.binread(qemu_log).match?(/^WGF_QEMU_RECEIVED #{TRANSFER_BYTES} /) }
  digest = Digest::SHA256.file(sent).hexdigest
  received = File.binread(qemu_log).scan(/^WGF_QEMU_RECEIVED #{TRANSFER_BYTES} ([0-9a-f]{64})\r?$/).last&.first
  raise "guest digest did not match source" unless received == digest

  puts "macOS QEMU Linux E2E: PASS (#{TRANSFER_BYTES} bytes, sha256=#{digest})"
ensure
  status = $!
  if status
    warn "macOS QEMU Linux E2E failed; tunnel logs follow."
    ["host.log", "qemu.log"].each do |log|
      path = File.join(root, log)
      warn File.read(path) if File.exist?(path)
    end
  end
  terminate(host_pid)
  terminate(qemu_pid)
  system("sudo", "-n", "route", "-n", "delete", "-host", GUEST_ADDRESS, "-interface", host_utun, out: File::NULL, err: File::NULL) if host_utun
  FileUtils.remove_entry(root)
end

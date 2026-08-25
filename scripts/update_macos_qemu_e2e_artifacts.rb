#!/usr/bin/env ruby
# frozen_string_literal: true

# Updates the Alpine netboot URL and checksums used by macos_qemu_e2e.rb.
# Without --branch, uses the latest Alpine stable release branch.

require "digest"
require "open3"
require "optparse"
require "tmpdir"

ARTIFACTS = %w[vmlinuz-virt initramfs-virt modloop-virt].freeze
SOURCE = File.expand_path("macos_qemu_e2e.rb", __dir__)
LATEST_STABLE_METADATA = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/latest-releases.yaml"

options = { write: false }
OptionParser.new do |parser|
  parser.banner = "Usage: #{File.basename($PROGRAM_NAME)} [--branch vX.Y] [--write]"
  parser.on("--branch BRANCH", "Alpine release branch, for example v3.24") { |value| options[:branch] = value }
  parser.on("--write", "Update macos_qemu_e2e.rb; otherwise print the proposed constants") { options[:write] = true }
end.parse!

def run!(*command)
  abort "command failed: #{command.join(" ")}" unless system(*command)
end

def capture!(*command)
  output, status = Open3.capture2e(*command)
  abort "command failed: #{command.join(" ")}\n#{output}" unless status.success?

  output
end

unless options[:branch]
  metadata = capture!("curl", "--fail", "--location", "--silent", "--show-error", LATEST_STABLE_METADATA)
  match = metadata.match(/title: "Netboot".*?^  branch: (v\d+\.\d+)$/m)
  abort "could not identify the latest stable Alpine netboot branch" unless match

  options[:branch] = match[1]
  warn "using latest stable Alpine branch #{options[:branch]}"
end
abort "--branch must match vX.Y" unless options[:branch].match?(/\Av\d+\.\d+\z/)

base_url = "https://dl-cdn.alpinelinux.org/alpine/#{options[:branch]}/releases/aarch64/netboot"
checksums = {}

Dir.mktmpdir("wgf-alpine-artifacts.") do |directory|
  ARTIFACTS.each do |artifact|
    path = File.join(directory, artifact)
    run!("curl", "--fail", "--location", "--retry", "3", "--output", path, "#{base_url}/#{artifact}")
    checksums[artifact] = Digest::SHA256.file(path).hexdigest
  end

end

constants = <<~RUBY
  ALPINE_NETBOOT = "#{base_url}"
  ALPINE_ARTIFACTS = {
    "vmlinuz-virt" => "#{checksums.fetch("vmlinuz-virt")}",
    "initramfs-virt" => "#{checksums.fetch("initramfs-virt")}",
    "modloop-virt" => "#{checksums.fetch("modloop-virt")}"
  }.freeze
RUBY

unless options[:write]
  puts constants
  exit
end

source = File.read(SOURCE)
updated = source.sub(/ALPINE_NETBOOT = .*?\nALPINE_ARTIFACTS = \{.*?\n\}\.freeze\n/m, constants)
abort "could not find Alpine artifact constants in #{SOURCE}" if updated == source

temporary = "#{SOURCE}.tmp"
File.write(temporary, updated)
File.rename(temporary, SOURCE)
puts "updated #{SOURCE}"

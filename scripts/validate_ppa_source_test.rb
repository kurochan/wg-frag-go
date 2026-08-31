#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "minitest/autorun"
require "tmpdir"
require_relative "validate_ppa_source"

class PpaSourceValidatorTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("wgf-ppa-validator-")
    @package_version = "0.4.1-1+noble1"
    @package_files = {
      "wg-frag-go_0.4.1.orig.tar.gz" => "orig",
      "wg-frag-go_#{@package_version}.debian.tar.xz" => "debian",
      "wg-frag-go_#{@package_version}.dsc" => "dsc"
    }
    @package_files.each { |name, content| File.write(File.join(@root, name), content) }
    write_changes
    write_manifest
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def test_accepts_valid_source_package
    assert_equal changes_path, validator.validate
  end

  def test_rejects_manifest_digest_mismatch
    File.write(File.join(@root, @package_files.keys.first), "changed")

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/checksum mismatch/, error.message)
  end

  def test_rejects_unmanifested_file
    File.write(File.join(@root, "unexpected"), "content")

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/manifest mismatch/, error.message)
  end

  def test_rejects_unsafe_manifest_filename
    manifest = File.read(File.join(@root, "SHA256SUMS"), encoding: Encoding::UTF_8)
    File.write(File.join(@root, "SHA256SUMS"), manifest.sub(@package_files.keys.first, "../outside"))

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/invalid SHA256SUMS entry/, error.message)
  end

  def test_rejects_repeated_control_field
    content = File.read(changes_path, encoding: Encoding::UTF_8)
    File.write(changes_path, content.sub("Version:", "Version: 0.4.1-1+noble1\nVersion:"))
    write_manifest

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/repeated Version field/, error.message)
  end

  def test_rejects_symlink
    target = @package_files.keys.first
    FileUtils.rm(File.join(@root, target))
    File.symlink("wg-frag-go_#{@package_version}.dsc", File.join(@root, target))

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/non-regular file/, error.message)
  end

  def test_rejects_wrong_series_version
    content = File.read(changes_path, encoding: Encoding::UTF_8)
    File.write(changes_path, content.sub(@package_version, "0.4.1-1+jammy1"))
    write_manifest

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/unexpected source package version/, error.message)
  end

  def test_rejects_different_files_field_set
    content = File.read(changes_path, encoding: Encoding::UTF_8)
    first_file = @package_files.keys.first
    File.write(changes_path, content.sub(/^ [0-9a-f]{32} \d+ net optional #{Regexp.escape(first_file)}\n/, ""))
    write_manifest

    error = assert_raises(PpaSourceValidator::Error) { validator.validate }
    assert_match(/different file sets/, error.message)
  end

  private

  def validator
    PpaSourceValidator::Validator.new(
      artifact_root: @root,
      series: "noble",
      tag: "v0.4.1",
      run_attempt: "1"
    )
  end

  def changes_name
    "wg-frag-go_#{@package_version}_source.changes"
  end

  def changes_path
    File.join(@root, changes_name)
  end

  def write_changes
    checksums = @package_files.map do |name, content|
      " #{Digest::SHA256.hexdigest(content)} #{content.bytesize} #{name}"
    end.join("\n")
    files = @package_files.map do |name, content|
      " #{Digest::MD5.hexdigest(content)} #{content.bytesize} net optional #{name}"
    end.join("\n")
    File.write(changes_path, <<~CHANGES)
      Format: 1.8
      Source: wg-frag-go
      Version: #{@package_version}
      Distribution: noble
      Architecture: source
      Checksums-Sha256:
      #{checksums}
      Files:
      #{files}
    CHANGES
  end

  def write_manifest
    entries = Dir.children(@root).sort.each_with_object([]) do |name, result|
      file = File.join(@root, name)
      next unless File.file?(file) && !File.symlink?(file) && name != "SHA256SUMS"

      result << "#{Digest::SHA256.file(file).hexdigest}  #{name}"
    end
    File.write(File.join(@root, "SHA256SUMS"), "#{entries.join("\n")}\n")
  end
end

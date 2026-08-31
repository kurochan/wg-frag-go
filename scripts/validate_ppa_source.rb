#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "optparse"
require "set"

module PpaSourceValidator
  class Error < StandardError; end

  SAFE_FILENAME = /\A[A-Za-z0-9][A-Za-z0-9.+~_-]*\z/.freeze
  SUPPORTED_SERIES = %w[jammy noble resolute].freeze

  class Validator
    def initialize(artifact_root:, series:, tag:, run_attempt:)
      @artifact_root = File.expand_path(artifact_root)
      @series = series
      @tag = tag
      @run_attempt = positive_integer(run_attempt, "workflow run attempt")
    end

    def validate
      validate_series
      entries = validate_directory
      manifest = parse_manifest
      validate_manifest(entries, manifest)

      changes_file = find_changes_file(entries)
      fields = parse_deb822(path(changes_file))
      validate_metadata(fields, changes_file)
      referenced_files = validate_checksums(fields.fetch("Checksums-Sha256"), manifest)
      validate_upload_files(fields.fetch("Files"), referenced_files)
      validate_file_sets(manifest.keys, changes_file, referenced_files)

      path(changes_file)
    rescue KeyError => e
      raise Error, "missing required field: #{e.key}"
    end

    private

    def validate_series
      return if SUPPORTED_SERIES.include?(@series)

      raise Error, "unsupported Ubuntu series: #{@series}"
    end

    def validate_directory
      raise Error, "artifact directory does not exist: #{@artifact_root}" unless Dir.exist?(@artifact_root)

      Dir.children(@artifact_root).each_with_object([]) do |filename, entries|
        validate_filename(filename)
        stat = File.lstat(path(filename))
        raise Error, "source package artifact contains a non-regular file: #{filename}" unless stat.file?

        entries << filename
      end
    end

    def parse_manifest
      manifest_path = path("SHA256SUMS")
      raise Error, "source package manifest is missing" unless File.file?(manifest_path) && !File.symlink?(manifest_path)

      manifest = {}
      File.foreach(manifest_path, encoding: Encoding::UTF_8, chomp: true).with_index(1) do |line, line_number|
        match = /\A([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9.+~_-]*)\z/.match(line)
        raise Error, "invalid SHA256SUMS entry at line #{line_number}" unless match

        digest = match[1]
        filename = match[2]
        if filename == "SHA256SUMS" || manifest.key?(filename)
          raise Error, "duplicate or recursive SHA256SUMS entry: #{filename}"
        end
        manifest[filename] = digest
      end
      raise Error, "source package manifest is incomplete" if manifest.size < 2

      manifest
    end

    def validate_manifest(entries, manifest)
      expected_entries = manifest.keys.to_set.add("SHA256SUMS")
      actual_entries = entries.to_set
      unless actual_entries == expected_entries
        unexpected = (actual_entries - expected_entries).to_a.sort
        missing = (expected_entries - actual_entries).to_a.sort
        raise Error, "source package manifest mismatch (unexpected=#{unexpected.inspect}, missing=#{missing.inspect})"
      end

      manifest.each do |filename, expected_digest|
        file_path = path(filename)
        unless File.file?(file_path) && !File.symlink?(file_path)
          raise Error, "missing or invalid manifested file: #{filename}"
        end
        actual_digest = Digest::SHA256.file(file_path).hexdigest
        raise Error, "source package checksum mismatch: #{filename}" unless actual_digest == expected_digest
      end
    end

    def find_changes_file(entries)
      changes_files = entries.grep(/_source\.changes\z/)
      unless changes_files.size == 1
        raise Error, "expected one source changes file, found #{changes_files.size}"
      end

      changes_files.fetch(0)
    end

    def parse_deb822(file_path)
      fields = {}
      current_field = nil

      File.foreach(file_path, encoding: Encoding::UTF_8, chomp: true).with_index(1) do |line, line_number|
        if line.empty?
          current_field = nil
        elsif (match = /\A([A-Za-z0-9-]+):(.*)\z/.match(line))
          name = match[1]
          raise Error, "repeated #{name} field in source changes file" if fields.key?(name)

          remainder = match[2]
          unless remainder.empty? || remainder.start_with?(" ")
            raise Error, "invalid #{name} field at line #{line_number}"
          end
          fields[name] = remainder.empty? ? [] : [remainder.delete_prefix(" ")]
          current_field = name
        elsif line.start_with?(" ", "\t")
          raise Error, "orphan continuation at line #{line_number}" unless current_field

          fields.fetch(current_field) << line.lstrip
        else
          raise Error, "invalid source changes syntax at line #{line_number}"
        end
      end

      fields
    end

    def validate_metadata(fields, changes_file)
      source_name = scalar_field(fields, "Source")
      package_version = scalar_field(fields, "Version")
      distribution = scalar_field(fields, "Distribution")
      architecture = scalar_field(fields, "Architecture")
      unless source_name == "wg-frag-go" && distribution == @series && architecture == "source"
        raise Error, "source changes metadata does not match the requested package and series"
      end

      tag_match = /\Av(\d+\.\d+\.\d+(?:-rc\.\d+)?)\z/.match(@tag)
      raise Error, "invalid release tag: #{@tag}" unless tag_match

      expected_upstream = tag_match[1].sub(/-rc\.(\d+)\z/, '~rc.\1')
      version_match = /\A#{Regexp.escape(expected_upstream)}-(\d+)\+#{Regexp.escape(@series)}(\d+)\z/.match(package_version)
      raise Error, "unexpected source package version: #{package_version}" unless version_match

      positive_integer(version_match[1], "Debian revision")
      series_attempt = positive_integer(version_match[2], "series build attempt")
      if series_attempt > @run_attempt
        raise Error, "series build attempt is newer than the workflow attempt"
      end

      expected_changes_file = "wg-frag-go_#{package_version}_source.changes"
      return if changes_file == expected_changes_file

      raise Error, "source changes filename does not match its package version"
    end

    def validate_checksums(lines, manifest)
      raise Error, "Checksums-Sha256 field is empty" if lines.empty?

      referenced_files = {}
      dsc_count = 0
      lines.each do |line|
        digest, size_text, filename, extra = line.split
        validate_filename(filename)
        unless extra.nil? && digest&.match?(/\A[0-9a-f]{64}\z/) && size_text&.match?(/\A\d+\z/)
          raise Error, "invalid checksum metadata for #{filename || "unknown file"}"
        end
        raise Error, "duplicate referenced filename: #{filename}" if referenced_files.key?(filename)
        raise Error, "referenced file is absent from SHA256SUMS: #{filename}" unless manifest.key?(filename)

        file_path = path(filename)
        actual_digest = Digest::SHA256.file(file_path).hexdigest
        actual_size = File.size(file_path)
        if actual_digest != digest || actual_size != Integer(size_text, 10)
          raise Error, "source changes checksum mismatch: #{filename}"
        end

        referenced_files[filename] = true
        dsc_count += 1 if filename.end_with?(".dsc")
      end
      if referenced_files.empty? || dsc_count != 1
        raise Error, "source changes file does not reference exactly one dsc file"
      end

      referenced_files.keys.to_set
    end

    def validate_upload_files(lines, referenced_files)
      raise Error, "Files field is empty" if lines.empty?

      upload_files = Set.new
      lines.each do |line|
        digest, size, section, priority, filename, extra = line.split
        validate_filename(filename)
        valid = extra.nil? && digest&.match?(/\A[0-9a-f]{32}\z/) && size&.match?(/\A\d+\z/) &&
          !section.to_s.empty? && !priority.to_s.empty?
        raise Error, "invalid Files metadata for #{filename || "unknown file"}" unless valid
        raise Error, "duplicate upload filename: #{filename}" if upload_files.include?(filename)

        upload_files.add(filename)
      end
      return if upload_files == referenced_files

      raise Error, "Files and Checksums-Sha256 contain different file sets"
    end

    def validate_file_sets(manifest_files, changes_file, referenced_files)
      package_files = manifest_files.to_set.delete(changes_file)
      return if package_files == referenced_files

      raise Error, "source package manifest contains unexpected package files"
    end

    def scalar_field(fields, name)
      values = fields.fetch(name)
      unless values.size == 1 && !values.fetch(0).empty?
        raise Error, "missing or repeated #{name} field in source changes file"
      end

      values.fetch(0)
    end

    def validate_filename(filename)
      raise Error, "invalid source package filename: #{filename.inspect}" unless SAFE_FILENAME.match?(filename.to_s)
    end

    def positive_integer(value, description)
      text = value.to_s
      raise Error, "invalid #{description}: #{text}" unless /\A[1-9]\d*\z/.match?(text)

      Integer(text, 10)
    end

    def path(filename)
      File.join(@artifact_root, filename)
    end
  end

  module_function

  def run(argv)
    options = {}
    parser = OptionParser.new do |opts|
      opts.on("--artifact-root PATH") { |value| options[:artifact_root] = value }
      opts.on("--series SERIES") { |value| options[:series] = value }
      opts.on("--tag TAG") { |value| options[:tag] = value }
      opts.on("--run-attempt NUMBER") { |value| options[:run_attempt] = value }
    end
    parser.parse!(argv)
    required = %i[artifact_root series tag run_attempt]
    missing = required.reject { |key| options.key?(key) }
    raise Error, "missing options: #{missing.join(", ")}" unless missing.empty?

    puts Validator.new(**options).validate
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    PpaSourceValidator.run(ARGV)
  rescue OptionParser::ParseError, PpaSourceValidator::Error => e
    warn "error: #{e.message}"
    exit 1
  end
end

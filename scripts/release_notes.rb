#!/usr/bin/env ruby
# frozen_string_literal: true

require "erb"
require "time"

module ReleaseNotes
  class Error < StandardError; end

  Entry = Struct.new(:version, :date, :bullets, keyword_init: true) do
    def debian_version
      "#{version.sub("-rc.", "~rc.")}-1"
    end

    def debian_date
      date.utc.strftime("%a, %d %b %Y %H:%M:%S +0000")
    end
  end

  VERSION = /\A(?:v)?(\d+\.\d+\.\d+(?:-rc\.\d+)?)\z/.freeze
  HEADING = /^##\s+v?(\d+\.\d+\.\d+(?:-rc\.\d+)?)\s+-\s+(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?)\s*$/.freeze
  DEBIAN_HEADER = /^wg-frag-go \(([^)]+)\) .+; urgency=.+$/.freeze

  module_function

  def normalize_version(value)
    match = VERSION.match(value)
    raise Error, "invalid release version: #{value.inspect}" unless match

    match[1]
  end

  def parse(path)
    entries = []
    current = nil

    File.foreach(path, encoding: Encoding::UTF_8, chomp: true).with_index(1) do |line, line_number|
      if (match = HEADING.match(line))
        entries << current if current
        current = Entry.new(version: match[1], date: parse_timestamp(match[2], line_number), bullets: [])
      elsif line.start_with?("##")
        raise Error, "#{path}:#{line_number}: invalid release heading"
      elsif line.start_with?("- ")
        raise Error, "#{path}:#{line_number}: bullet is outside a release" unless current

        current.bullets << line.delete_prefix("- ")
      elsif line.empty? || line.start_with?("# ")
        next
      elsif current
        raise Error, "#{path}:#{line_number}: release entries only support single-line bullets"
      else
        raise Error, "#{path}:#{line_number}: unexpected content"
      end
    end
    entries << current if current

    raise Error, "#{path}: no release entries" if entries.empty?
    ensure_unique_entries(path, entries)
    entries.each do |entry|
      raise Error, "#{path}: #{entry.version} has no bullets" if entry.bullets.empty?
    end
    entries
  end

  def render_debian(entries, template_path)
    template = ERB.new(File.read(template_path, encoding: Encoding::UTF_8), trim_mode: "-")
    template.result(RenderContext.new(entries).get_binding)
  end

  def parse_debian(path)
    entries = []
    current = nil
    current_bullet = nil

    File.foreach(path, encoding: Encoding::UTF_8, chomp: true).with_index(1) do |line, line_number|
      if (match = DEBIAN_HEADER.match(line))
        entries << current if current
        current = Entry.new(version: normalize_debian_version(match[1]), date: nil, bullets: [])
        current_bullet = nil
      elsif line.start_with?("  * ")
        raise Error, "#{path}:#{line_number}: bullet is outside an entry" unless current

        current_bullet = line.delete_prefix("  * ")
        current.bullets << current_bullet
      elsif line.start_with?("    ") && current_bullet
        current.bullets[-1] = "#{current.bullets[-1]} #{line.strip}"
      elsif line.start_with?(" -- ") || line.empty?
        next
      elsif current
        raise Error, "#{path}:#{line_number}: unsupported Debian changelog content"
      end
    end
    entries << current if current

    raise Error, "#{path}: no wg-frag-go entries" if entries.empty?
    entries
  end

  def check_sync(notes_entries, debian_entries)
    expected_versions = notes_entries.map(&:version)
    actual_versions = debian_entries.map(&:version)
    unless expected_versions == actual_versions
      raise Error, "version mismatch: RELEASE_NOTES.md=#{expected_versions.join(", ")}; debian/changelog=#{actual_versions.join(", ")}"
    end

    notes_entries.zip(debian_entries).each do |notes_entry, debian_entry|
      next if notes_entry.bullets == debian_entry.bullets

      raise Error, "bullet mismatch for #{notes_entry.version}"
    end
  end

  def find_entry(entries, version)
    normalized = normalize_version(version)
    entry = entries.find { |candidate| candidate.version == normalized }
    raise Error, "release version #{normalized} is not present in RELEASE_NOTES.md" unless entry

    entry
  end

  def github_highlights(entry)
    (["## Highlights", ""] + entry.bullets.map { |bullet| "- #{bullet}" }).join("\n") + "\n"
  end

  def parse_timestamp(value, line_number)
    return Time.utc(*value.split("-").map(&:to_i)) unless value.include?("T")

    Time.iso8601(value)
  rescue ArgumentError
    raise Error, "RELEASE_NOTES.md:#{line_number}: invalid UTC release timestamp: #{value.inspect}"
  end
  private_class_method :parse_timestamp

  def ensure_unique_entries(path, entries)
    duplicates = entries.group_by(&:version).select { |_version, group| group.length > 1 }.keys
    return if duplicates.empty?

    raise Error, "#{path}: duplicate release versions: #{duplicates.join(", ")}"
  end
  private_class_method :ensure_unique_entries

  def normalize_debian_version(value)
    upstream = value.sub(/-[0-9][^-]*\z/, "")
    normalize_version(upstream.sub("~rc.", "-rc."))
  end
  private_class_method :normalize_debian_version

  class RenderContext
    def initialize(entries)
      @entries = entries
    end

    attr_reader :entries

    def get_binding
      binding
    end

    def format_bullet(text)
      prefix = "  * "
      continuation = "    "
      width = 79
      words = text.split(/\s+/)
      lines = []
      line = prefix.dup

      words.each do |word|
        separator = line == prefix || line == continuation ? "" : " "
        if line.length + separator.length + word.length > width && line != prefix && line != continuation
          lines << line.rstrip
          line = +"#{continuation}#{word}"
        else
          line << separator << word
        end
      end
      lines << line.rstrip
      lines.join("\n")
    end
  end
end

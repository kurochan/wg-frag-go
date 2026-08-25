#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"
require_relative "release_notes"

options = { input: "RELEASE_NOTES.md", changelog: "debian/changelog" }

OptionParser.new do |parser|
  parser.banner = "Usage: #{File.basename($PROGRAM_NAME)} [options]"
  parser.on("--version VERSION", "Require this release tag or version to be present") { |value| options[:version] = value }
  parser.on("--input PATH", "Release notes source (default: #{options[:input]})") { |value| options[:input] = value }
  parser.on("--changelog PATH", "Debian changelog (default: #{options[:changelog]})") { |value| options[:changelog] = value }
end.parse!

begin
  entries = ReleaseNotes.parse(options[:input])
  ReleaseNotes.find_entry(entries, options[:version]) if options[:version]
  ReleaseNotes.check_sync(entries, ReleaseNotes.parse_debian(options[:changelog]))
  puts "RELEASE_NOTES.md and debian/changelog are synchronized."
rescue ReleaseNotes::Error => e
  warn e.message
  exit 1
end

#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"
require_relative "release_notes"

options = {
  input: "RELEASE_NOTES.md",
  output: "debian/changelog",
  template: "debian/changelog.erb"
}

OptionParser.new do |parser|
  parser.banner = "Usage: #{File.basename($PROGRAM_NAME)} [options]"
  parser.on("--input PATH", "Release notes source (default: #{options[:input]})") { |value| options[:input] = value }
  parser.on("--output PATH", "Debian changelog destination (default: #{options[:output]})") { |value| options[:output] = value }
  parser.on("--template PATH", "ERB template (default: #{options[:template]})") { |value| options[:template] = value }
end.parse!

begin
  entries = ReleaseNotes.parse(options[:input])
  rendered = ReleaseNotes.render_debian(entries, options[:template])
  existing = File.read(options[:output], encoding: Encoding::UTF_8) if File.exist?(options[:output])
  File.write(options[:output], rendered) unless existing == rendered
rescue ReleaseNotes::Error => e
  warn e.message
  exit 1
end

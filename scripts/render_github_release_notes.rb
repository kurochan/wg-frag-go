#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"
require_relative "release_notes"

options = { input: "RELEASE_NOTES.md" }

parser = OptionParser.new do |option_parser|
  option_parser.banner = "Usage: #{File.basename($PROGRAM_NAME)} --version VERSION [options]"
  option_parser.on("--version VERSION", "Release tag or version") { |value| options[:version] = value }
  option_parser.on("--input PATH", "Release notes source (default: #{options[:input]})") { |value| options[:input] = value }
end
parser.parse!
abort parser.to_s unless options[:version]

begin
  entry = ReleaseNotes.find_entry(ReleaseNotes.parse(options[:input]), options[:version])
  print ReleaseNotes.github_highlights(entry)
rescue ReleaseNotes::Error => e
  warn e.message
  exit 1
end

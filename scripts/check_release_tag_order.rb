#!/usr/bin/env ruby
# frozen_string_literal: true

require "open3"
require "optparse"

module ReleaseTagOrder
  class Error < StandardError; end

  class Version
    include Comparable

    PATTERN = /\Av(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-rc\.(?<rc>\d+))?\z/

    attr_reader :major, :minor, :patch, :rc, :tag

    def self.parse(tag)
      match = PATTERN.match(tag)
      raise Error, "invalid release tag #{tag.inspect}" unless match

      new(tag, match[:major].to_i, match[:minor].to_i, match[:patch].to_i, match[:rc]&.to_i)
    end

    def initialize(tag, major, minor, patch, rc)
      @tag = tag
      @major = major
      @minor = minor
      @patch = patch
      @rc = rc
    end

    def <=>(other)
      numeric = [major, minor, patch] <=> [other.major, other.minor, other.patch]
      return numeric unless numeric.zero?

      return 0 if rc == other.rc
      return 1 if rc.nil?
      return -1 if other.rc.nil?

      rc <=> other.rc
    end
  end

  module_function

  def check(tag, tags)
    target = Version.parse(tag)
    versions = tags.each_with_object([]) do |candidate, result|
      begin
        result << Version.parse(candidate)
      rescue Error
        nil
      end
    end
    previous = versions.reject { |candidate| candidate.tag == target.tag }.max

    if previous && target <= previous
      raise Error, "release tag #{target.tag} must be later than existing release tag #{previous.tag}"
    end

    puts "release tag #{target.tag} follows #{previous&.tag || "no earlier release tag"}"
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  parser = OptionParser.new do |option_parser|
    option_parser.banner = "Usage: #{File.basename($PROGRAM_NAME)} --version TAG"
    option_parser.on("--version TAG", "Release tag to validate") { |value| options[:version] = value }
  end
  parser.parse!
  abort parser.to_s unless options[:version]

  tags, status = Open3.capture2("git", "tag", "--list", "v*")
  abort "could not list Git tags" unless status.success?

  begin
    ReleaseTagOrder.check(options[:version], tags.lines(chomp: true))
  rescue ReleaseTagOrder::Error => e
    warn e.message
    exit 1
  end
end

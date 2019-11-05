$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "tyrant"

require "minitest/autorun"

require "trailblazer/test/assertions"

Minitest::Spec.module_eval do
  include Trailblazer::Test::Assertions

  module AssertExposes
    def assert_exposes(hash, expected)
      return super(hash, expected, reader: :[]) if hash.is_a?(Hash)
      return super
    end
  end
  include AssertExposes
end

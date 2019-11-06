require "tyrant/version"

require "trailblazer/activity"
require "trailblazer/activity/dsl/linear"
require "trailblazer/developer"

module Tyrant
  module_function

  def call(activity, ctx)
    signal, (ctx, _) = Trailblazer::Developer.wtf?(activity, [ctx, {}])
    return ctx, signal.to_h[:semantic] == :success
  end
end

require "tyrant/auth"

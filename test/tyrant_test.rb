require "test_helper"

require "trailblazer/activity"
require "trailblazer/activity/dsl/linear"
require "trailblazer/developer"

module Tyrant
  module_function

  def call(activity, ctx)
    signal, (ctx, _) = Trailblazer::Developer.wtf?(activity, [ctx, {}])
    ctx
  end

  require "securerandom"
  require "openssl"

  module Auth
    module_function

    def encrypt_value(ctx, value:, cipher_key:, **)
      cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').encrypt
      cipher.key = Digest::SHA1.hexdigest(cipher_key)[0..23] # ArgumentError: key must be 24 bytes
      s = cipher.update(value) + cipher.final

      ctx[:encrypted_value] = s.unpack('H*')[0].upcase
    end

    def decrypt_value(ctx, encrypted_value:, cipher_key:, **)
      cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
      cipher.key = Digest::SHA1.hexdigest(cipher_key)[0..23]
      s = [encrypted_value].pack("H*").unpack("C*").pack("c*")

      ctx[:decrypted_value] = cipher.update(s) + cipher.final
    end


    module State
      module_function
      def password_assigned(ctx, **)
        ctx[:state] = "password assigned"
      end
    end

    def timestamp(ctx, **)
      ctx[:created_at] = DateTime.now
    end

    def des_assigned(ctx, **)
      ctx[:type] = "des-cipher"
    end

    require 'dry-struct'

    module Types
      include Dry.Types()
    end

    class Credentials < Dry::Struct
      attribute :username, Types::String
      attribute :password, Types::String
      attribute :created_at, Types::DateTime
      attribute :state, Types::String
      attribute :type, Types::String
    end
  end # Auth
end

class TyrantTest < Minitest::Spec
  let(:cipher_key) { "e1e1cc87asdfasdfasdfasfdasdfasdfasvhnfvbdb" }

  it "encrypt_value / decrypt_value" do
    api_key = "720fa5a6-9a83-4290-9542-86502bc4fb54"

    activity = Class.new(Trailblazer::Activity::Railway) do
      step Tyrant::Auth.method(:encrypt_value)
      step Tyrant::Auth.method(:decrypt_value)
    end

    ctx = Tyrant.(activity, value: api_key, cipher_key: cipher_key)

    ctx.inspect.must_equal %{{:value=>\"720fa5a6-9a83-4290-9542-86502bc4fb54\", :cipher_key=>\"e1e1cc87asdfasdfasdfasfdasdfasdfasvhnfvbdb\", :encrypted_value=>\"CC0D7407C3C8B71A8B601A6DDB49CA058EE5FB3F6AD1CDC268C7C72B6CDBA222DA66818AAB12256F\", :decrypted_value=>\"720fa5a6-9a83-4290-9542-86502bc4fb54\"}}



    # username:   "rolf"
    # password:   "asdfasdffadfasf" (random, NOT encrypted)
    # created_at: XX/XX/XXXX
    # state:      "password assigned"
    # [type:      "api_key"]
  end

  it "sample flow of creating an API key" do
    activity = Class.new(Trailblazer::Activity::Railway) do
      step :validate
      step :create_random_key
      step Tyrant::Auth.method(:encrypt_value), input: {random_key: :value, cipher_key: :cipher_key}
      step Tyrant::Auth::State.method(:password_assigned)
      step Tyrant::Auth.method(:des_assigned)
      step Tyrant::Auth.method(:timestamp)

      step :normalize
      # step Tyrant::Auth.method(:decrypt_value)

      def create_random_key(ctx, **)
        ctx[:random_key] = SecureRandom.uuid
      end

      def validate(ctx, username:, **)
        username.size > 0
      end

      def normalize(ctx, username:, encrypted_value:, created_at:, state:, type:, **)
        ctx[:api_auth_data] = Tyrant::Auth::Credentials.new({username: username, password: encrypted_value, created_at: created_at, state: state, type: type}) # TODO: use Tyrant "object"
      end
    end

    ctx = Tyrant.(activity, cipher_key: cipher_key, username: "apotonick@gmail.com")

    assert_exposes ctx[:api_auth_data].to_h,#.must_equal({})
      username: "apotonick@gmail.com",
      password: ->(actual:, **) { actual =~ /^\w+$/ },
      state:    "password assigned",
      type:     "des-cipher",
      created_at: ->(actual:, **) { actual < DateTime.now }

  end
end

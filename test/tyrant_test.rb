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
  end
end

class TyrantTest < Minitest::Spec
  it "encrypt_value / decrypt_value" do

    cipher_key = "e1e1cc87asdfasdfasdfasfdasdfasdfasvhnfvbdb"

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
end

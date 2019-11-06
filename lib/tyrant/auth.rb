require "securerandom"
require "openssl"

module Tyrant
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

    def compare_passwords(ctx, decrypted_value:, password:, **)
      password == decrypted_value
    end


    module State
      module_function
      def password_assigned(ctx, **)
        ctx[:state] = "password assigned"
      end
    end

    def timestamp(ctx, **)
      ctx[:created_at] = DateTime.now.strftime("%+") # DISCUSS: should this be DateTime and then transform in to_json?
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
      attribute :created_at, Types::String # DISCUSS: should this be DateTime and then transform in to_json?
      attribute :state, Types::String
      attribute :type, Types::String
    end
  end # Auth
end

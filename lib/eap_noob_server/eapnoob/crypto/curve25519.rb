# frozen_string_literal: true

module EAPNOOBServer
  module EAPNOOB
    module Crypto
      # Implementation of Curve25519 algorithm
      # @todo not yet functional
      class Curve25519
        def initialize(priv_s = nil)
          @own_key = if priv_s
                       X25519::Scalar.new(priv_s)
                     else
                       X25519::Scalar.generate
                     end
          @peer_key = nil
        end

        def pks
          {
            'kty': 'OKP',
            'crv': 'X25519',
            'x': Base64.urlsafe_encode64(@own_key.public_key.to_bytes, padding: false)
          }
        end

        def add_peer_key(key_string)
          @peer_key = key_string
        end

        def calculate_shared_secret
          peer = X25519::MontgomeryU.new(@peer_key)
          @own_key.diffie_hellman(peer).to_bytes
        end

        # Calculate the hash of the given input using the corresponding hash function as defined by the cryptosuite
        # @param [String] input JSON string for the input
        # @return [String] Hash output as byte string
        def calculate_hash(input)
          OpenSSL::Digest::SHA256.digest(input)
        end

        # Calculate the HMAC of the given input using the corresponding key and hash function defined by the cryptosuite
        # @param [String] key symmetric key as byte string
        # @param [String] input JSON string for the HMAC input
        # @return [String] HMAC output as byte string
        def calculate_hmac(key, input)
          OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, key, input)
        end
      end
    end
  end
end

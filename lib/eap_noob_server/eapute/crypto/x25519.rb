# frozen_string_literal: true

module EAPNOOBServer
  module EAPUTE
    module Crypto
      # Implementation of X25519 algorithm
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
            -1 => 4,
            -2 =>  @own_key.public_key.to_bytes.b
          }
        end

        def add_peer_key(key_string)
          @peer_key = key_string
        end

        def calculate_shared_secret
          peer = X25519::MontgomeryU.new(@peer_key)
          @own_key.diffie_hellman(peer).to_bytes
        end
      end
    end
  end
end

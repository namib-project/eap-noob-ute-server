# frozen_string_literal: true

module EAPNOOBServer
  module EAPNOOB
    module Crypto
      # Class for handling the NIST-P256 algorithm for EAP-NOOB
      # @todo Not yet functional
      class NIST_P256
        def initialize
          @key = OpenSSL::PKey::EC.generate('prime256v1')
        end

        def pks
          {
            'crv': 'P-256',
            'kty': 'EC'
          }
        end
      end
    end
  end
end

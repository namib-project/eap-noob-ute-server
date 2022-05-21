# frozen_string_literal: true

# Require needed ruby modules
require 'logger'
require 'rbnacl'
require 'json'
require 'openssl'
require 'x25519'
require 'base64'
require 'active_record'
require 'cbor'

# Require all library files
require_relative 'eap_noob_server/version'
require_relative 'eap_noob_server/radius'
require_relative 'eap_noob_server/eap'
require_relative 'eap_noob_server/eapnoob'

# EAP-NOOB Server including methods for RADIUS and EAP
module EAPNOOBServer
  class << self
    attr_writer :logger

    def logger
      @logger ||= ::Logger.new($stderr).tap do |log|
        log.progname = 'EAPNOOBServer'
      end
    end
  end
end

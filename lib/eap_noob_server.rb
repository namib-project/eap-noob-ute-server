# Require needed ruby modules
require 'logger'

# Require all library files
require_relative 'eap_noob_server/version'
require_relative 'eap_noob_server/radius'
require_relative 'eap_noob_server/eap'
require_relative 'eap_noob_server/eapnoob'

module EAPNOOBServer

  class << self
    attr_writer :logger
    def logger
      @logger ||= ::Logger.new($stderr).tap do |log|
        log.progname = "EAPNOOBServer"
      end
    end
  end
end

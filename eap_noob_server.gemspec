# frozen_string_literal: true

require_relative 'lib/eap_noob_server/version'

Gem::Specification.new do |spec|
  spec.name           = 'eap_noob_server'
  spec.version        = EAPNOOBServer::VERSION
  spec.authors        = ['Jan-Frederik Rieckers']
  spec.email          = ['rieckers@uni-bremen.de']

  spec.files          = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end

  spec.summary        = 'A simple proof of concept EAP-NOOB server'
  spec.description    = 'A simple proof of concept server implementation for EAP-NOOB (https://datatracker.ietf.org/doc/draft-ietf-emu-eap-noob/)'
  spec.homepage       = 'https://gitlab.informatik.uni-bremen.de/namib-master/network-components/eap-noob-server'
  spec.bindir         = 'bin'
  spec.executables    = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths  = ['lib']
  spec.licenses       = %w[MIT Apache-2.0]

  spec.add_runtime_dependency 'activerecord'
  spec.add_runtime_dependency 'cbor', '~>0.5.9.6'
  spec.add_runtime_dependency 'cbor-deterministic', '~>0.1.3'
  spec.add_runtime_dependency 'rbnacl', '~>7.1.1'
  spec.add_runtime_dependency 'sqlite3', '~>1.4'
  spec.add_runtime_dependency 'x25519', '~>1.0.9'
  spec.required_ruby_version = '>=2.7.0'
end

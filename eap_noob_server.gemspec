require_relative 'lib/eap_noob_server/version'

Gem::Specification.new do |spec|
  spec.name           = 'eap_noob_server'
  spec.version        = EAPNOOBServer::VERSION
  spec.authors        = ['Jan-Frederik Rieckers']
  spec.email          = ['rieckers@uni-bremen.de']

  spec.files          = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end

  spec.summary        = %q{A simple proof of concept EAP-NOOB server}
  spec.description    = %q{A simple proof of concept server implementation for EAP-NOOB (https://datatracker.ietf.org/doc/draft-ietf-emu-eap-noob/)}
  spec.homepage       = "https://gitlab.informatik.uni-bremen.de/namib-master/network-components/eap-noob-server"
  spec.bindir         = "bin"
  spec.executables    = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths  = ["lib"]
  spec.licenses       = ['MIT', 'Apache-2.0']
end

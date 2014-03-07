# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'presstore/version'

Gem::Specification.new do |spec|
  spec.name          = 'presstore'
  spec.version       = PresSTORE::VERSION
  spec.authors       = ['John Whitson']
  spec.email         = ['john.whitson@gmail.com']
  spec.summary       = %q{A Library for Interacting with Archiware's PresSTORE Application}
  spec.description   = %q{}
  spec.homepage      = ''
  spec.license       = ''

  spec.required_ruby_version     = '>= 1.8.7'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.5'
  spec.add_development_dependency 'rake'

  spec.add_runtime_dependency 'json'
  spec.add_runtime_dependency 'net-ssh'
  spec.add_runtime_dependency 'plist', '~> 3'
end

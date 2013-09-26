require 'rake'

Gem::Specification.new do |s|
  s.name        = 'pcap_tools'
  s.version     = '0.0.3'
  s.authors     = ['Bertrand Paquet']
  s.email       = 'bertrand.paquet@gmail.com'
  s.summary     = 'Tools for extracting data from pcap files'
  s.homepage    = 'https://github.com/bpaquet/pcap_tools'
  s.executables << 'pcap_tools_http'
  s.files       = `git ls-files`.split($/)
  s.license     = 'BSD'

  s.add_runtime_dependency('packetfu', '>= 1.1.9')
end

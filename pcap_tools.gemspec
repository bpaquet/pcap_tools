require 'rake'

Gem::Specification.new do |s|
  s.name        = 'pcap_tools'
  s.version     = '0.0.5'
  s.authors     = ['Bertrand Paquet']
  s.email       = 'bertrand.paquet@gmail.com'
  s.summary     = 'Tools for extracting data from pcap files'
  s.homepage    = 'https://github.com/bpaquet/pcap_tools'
  s.executables << 'pcap_tools'
  s.files       = `git ls-files`.split($/)
  s.license     = 'BSD'

  s.add_dependency('bindata', '>= 1.6.0')
end

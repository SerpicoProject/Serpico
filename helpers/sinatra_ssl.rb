require 'webrick/https'
require 'openssl'

# I can't take credit for this, this is from a stackoverflow article
# http://stackoverflow.com/questions/2362148/how-to-enable-ssl-for-a-standalone-sinatra-app

module Sinatra
  class Application
    def self.run!
      server_options = {
        :Port => port,
        :SSLEnable => use_ssl,
        :BindAddress => bind_address,
      }
      if (use_ssl) then
        certificate_content = File.open(ssl_certificate).read
        key_content = File.open(ssl_key).read
        server_options[:SSLCertificate] = OpenSSL::X509::Certificate.new(certificate_content)
        server_options[:SSLPrivateKey] = OpenSSL::PKey::RSA.new(key_content)
        server_options[:SSLVerifyClient] = OpenSSL::SSL::VERIFY_NONE
      end
      
      Rack::Handler::WEBrick.run self, server_options do |server|
        [:INT, :TERM].each { |sig| trap(sig) { server.stop } }
        server.threaded = settings.threaded if server.respond_to? :threaded=
        set :running, true
      end
    end
  end
end

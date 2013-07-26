require 'webrick/https'
require 'webrick'
require 'openssl'

# I can't take credit for this, it generates a self signed cert everytime it's run
# http://blog.divebomb.org/2012/01/ruby-sinatra-and-ssl/

module Sinatra
  class Application
    def self.run!

		name = "/C=US/ST=Here/L=There/O=Where/CN=serpico"
		ca   = OpenSSL::X509::Name.parse(name)
		key = OpenSSL::PKey::RSA.new(1024)
		crt = OpenSSL::X509::Certificate.new
		crt.version = 2
		crt.serial  = 1
		crt.subject = ca
		crt.issuer = ca
		crt.public_key = key.public_key
		crt.not_before = Time.now
		crt.not_after  = Time.now + 1 * 365 * 24 * 60 * 60 # 1 year
		crt.sign key, OpenSSL::Digest::SHA1.new
		
		server_options = {
			:Port               => 8443,
			:SSLEnable          => true,
			:SSLVerifyClient    => OpenSSL::SSL::VERIFY_NONE,
			:SSLCertificate     => crt,
			:SSLPrivateKey      => key,
			:SSLCertName        => [[ "CN", "A" ]],
		}

      Rack::Handler::WEBrick.run self, server_options do |server|
        [:INT, :TERM].each { |sig| trap(sig) { server.stop } }
        server.threaded = settings.threaded if server.respond_to? :threaded=
        set :running, true
      end
    end
  end
end

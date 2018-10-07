require 'bundler/setup'
require 'webrick/https'
require 'openssl'
require 'json'
require './server.rb'
require './config'

## SSL Settings
ssl_certificate = Config['ssl_certificate']
ssl_key = Config['ssl_key']
use_ssl = Config['use_ssl']
port = Config['port']
bind_address = Config['bind_address']

server_options = {
  Port: port,
  Host: bind_address
}

if Config['show_exceptions'].to_s.casecmp('false').zero? || !(Config['show_exceptions'])
  puts "|+| [#{DateTime.now.strftime('%d/%m/%Y %H:%M')}] Sending Webrick logging to /dev/null.."
  server_options[:Logger] = WEBrick::Log.new(File.open(File::NULL, 'w'))
  server_options[:AccessLog] = []
end

if use_ssl
  certificate_content = File.open(ssl_certificate).read
  key_content = File.open(ssl_key).read
  server_options[:SSLEnable] = true
  server_options[:SSLCertificate] = OpenSSL::X509::Certificate.new(certificate_content)
  server_options[:SSLPrivateKey] = OpenSSL::PKey::RSA.new(key_content)
  server_options[:SSLVerifyClient] = OpenSSL::SSL::VERIFY_NONE

  no_ssl3 = OpenSSL::SSL::OP_NO_SSLv3
  no_ssl2 = OpenSSL::SSL::OP_NO_SSLv2
  no_compression = OpenSSL::SSL::OP_NO_COMPRESSION
  ssl_options = no_ssl2 + no_ssl3 + no_compression
  server_options[:SSLOptions] = ssl_options
  server_options[:SSLVersion] = :TLSv1_2

  if(Config.key?('ssl_ciphers'))
      cz = Config['ssl_ciphers']
  else
      # SSL Ciphers
      cz = ['ECDHE-RSA-AES128-GCM-SHA256','ECDHE-RSA-AES256-GCM-SHA384',
           'ECDHE-RSA-AES128-CBC-SHA','ECDHE-RSA-AES256-CBC-SHA',
           'AES128-GCM-SHA256','AES256-GCM-SHA384','AES128-SHA256',
           'AES256-SHA256','AES128-SHA','AES256-SHA']
  end

  CIPHERS = cz.push("TLSv1.2","!aNULL","!eNULL","!SSLv2","!SSLv3")
  server_options[:SSLCiphers] = CIPHERS.join(":")

end

Rack::Handler::WEBrick.run Server, server_options

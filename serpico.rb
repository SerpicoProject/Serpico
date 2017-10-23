require "bundler/setup"
require 'webrick/https'
require 'openssl'
require 'json'
require "./server.rb"
config_options = Server.settings.config_options

## SSL Settings
ssl_certificate = config_options["ssl_certificate"]
ssl_key = config_options["ssl_key"]
use_ssl = config_options["use_ssl"]
port = config_options["port"]
bind_address =  config_options["bind_address"]

server_options = {
  :Port => port,
  :BindAddress => bind_address,
}

if config_options["show_exceptions"].to_s.downcase == "false" or (not config_options["show_exceptions"])
  puts "|+| [#{DateTime.now.strftime("%d/%m/%Y %H:%M")}] Sending Webrick logging to /dev/null.."
  server_options[:Logger] = WEBrick::Log.new(File.open(File::NULL, 'w'))
  server_options[:AccessLog] = []
end


if (use_ssl) then
  certificate_content = File.open(ssl_certificate).read
  key_content = File.open(ssl_key).read
  server_options[:SSLEnable] = true
  server_options[:SSLCertificate] = OpenSSL::X509::Certificate.new(certificate_content)
  server_options[:SSLPrivateKey] = OpenSSL::PKey::RSA.new(key_content)
  server_options[:SSLVerifyClient] = OpenSSL::SSL::VERIFY_NONE
end

Rack::Handler::WEBrick.run Server, server_options
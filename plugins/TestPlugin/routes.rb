require 'sinatra'

# List current reports
get '/TestPlugin/hello' do
	haml :'../plugins/TestPlugin/views/test_plugin', :encode_html => true
end

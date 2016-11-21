require 'rubygems'
require './model/master.rb'

if ARGV.size < 1
	# With no arguments a list of users is dumped
	puts "\n ****Usage: give_plugin_access.rb username \n"

	exit
end

username = ARGV[0]
user = User.first(:username => username)

if not user
	puts "|+| #{username} not found"
	exit
end

user.update(:plugin => true)
puts "|+| #{username} is updated to upload plugins"
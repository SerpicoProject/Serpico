require 'rubygems'
require './model/master.rb'

if ARGV.size < 3
	# With no arguments a list of users is dumped
	puts "\n ****Usage: create_user.rb username password level \n"
	
	users = User.all

	puts "\n Current Users"
	puts "Username \t Type \t Created At \n "
	
	users.each do |u|
		puts "#{u.username} \t #{u.type} \t #{u.created_at}"
	end
	puts "\n"
	exit
end

user = User.new
user.username = ARGV[0]
user.password = ARGV[1]
user.type = ARGV[2]
user.auth_type = "Local"
user.save

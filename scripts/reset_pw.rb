require 'rubygems'
require './model/master.rb'

user = User.first

print "Would you like to change the password for #{user.username} (Y/n)  "

change = gets.chomp.downcase

if change == "y" or change == ""

	password = rand(36**10).to_s(36)

    user.update(:type => "Administrator", :auth_type => "Local", :password => password)

	puts "User successfully updated."
	
	puts "\t\t New password is : #{password} \n\n"
else
	puts "Exiting..."
end

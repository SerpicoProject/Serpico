require 'rubygems'
require './model/master.rb'
require './helpers/xslt_generation'

userx = User.first

# If there are no users, create a first user
if !userx
	puts "No users in the database, creating a first user. \n"
	
	puts "Please enter username (default: administrator):  "
	username = gets.chomp
	username = "administrator" if username == ""

	puts "Generating random password and adding the Administrator with username #{username}..."
	
	password = rand(36**10).to_s(36)

	exists = User.first(:username => username)
	
	if exists
		puts "That username already exists. Please use reset_pw.rb to reset a password"		
	else
		user = User.new
		user.username = username
		user.password = password
		user.type = "Administrator"
		user.auth_type = "Local"
		user.save

		puts "Please use the following login credentials"
		puts "\t \t \t ****  #{username} : #{password} ****"

	end
else
	puts "Skipping username creation (users exist), please use the create_user.rb script to add a user."
end

# add the Default templates into the DB
templates = Xslt.first

if !templates
	puts "Adding the Serpico Default Report Template"

	xslt_file = "./templates/#{rand(36**36).to_s(36)}.xslt"
	docx = "./templates/Serpico - Report.docx"
	
	xslt = generate_xslt(docx)
	if xslt =~ /Error file DNE/
		return "ERROR!!!!!!"
	end

	# open up a file handle and write the attachment
	File.open(xslt_file, 'wb') {|f| f.write(xslt) }	
	
	# delete the file data from the attachment
	datax = Hash.new
	datax["docx_location"] = "#{docx}"
	datax["xslt_location"] = "#{xslt_file}"	
	datax["description"] = 	"Default Serpico Report"
	datax["report_type"] = "Default Template"
	report = Xslt.new(datax)
	report.save

	puts "Adding the Serpico Default Finding Template"

	xslt_file = "./templates/#{rand(36**36).to_s(36)}.xslt"
	docx = "./templates/Serpico - Finding.docx"
	
	xslt = generate_xslt(docx)
	if xslt =~ /Error file DNE/
		return "ERROR!!!!!!"
	end

	# open up a file handle and write the attachment
	File.open(xslt_file, 'wb') {|f| f.write(xslt) }	
	
	# delete the file data from the attachment
	datax = Hash.new
	datax["docx_location"] = "#{docx}"
	datax["xslt_location"] = "#{xslt_file}"	
	datax["description"] = 	"Default Serpico Finding"
	datax["report_type"] = "Default Finding"
	datax["finding_template"] = true
	report = Xslt.new(datax)
	report.save

	puts "Adding the Serpico Default Status Template"

	xslt_file = "./templates/#{rand(36**36).to_s(36)}.xslt"
	docx = "./templates/Serpico - Finding.docx"
	
	xslt = generate_xslt(docx)
	if xslt =~ /Error file DNE/
		return "ERROR!!!!!!"
	end

	# open up a file handle and write the attachment
	File.open(xslt_file, 'wb') {|f| f.write(xslt) }	
	
	# delete the file data from the attachment
	datax = Hash.new
	datax["docx_location"] = "#{docx}"
	datax["xslt_location"] = "#{xslt_file}"	
	datax["description"] = 	"Default Serpico Status"
	datax["report_type"] = "Default Status"
	datax["status_template"] = true
	report = Xslt.new(datax)
	report.save		

else
	puts "Skipping XSLT creation, templates exist." 
end


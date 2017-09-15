require 'sinatra'
require 'zip'

config_options = JSON.parse(File.read('./config.json'))

# set the report_assessment_types for <1.2 versions of Serpico
unless config_options["report_assessment_types"]
    config_options["report_assessment_types"] = ["Network Internal","External","Web application","Physical","Social engineering","Configuration audit"]
end

######
# Admin Interfaces
######

get '/admin/' do
    redirect to("/no_access") if not is_administrator?
    @admin = true

    haml :admin, :encode_html => true
end

get '/admin/add_user' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    haml :add_user, :encode_html => true
end

# serve a copy of the code
get '/admin/pull' do
    redirect to("/no_access") if not is_administrator?

	if File.exists?("./export.zip")
		send_file "./export.zip", :filename => "export.zip", :type => 'Application/octet-stream'
	else
		"No copy of the code available. Run scripts/make_export.sh."
	end
end

#create DB backup
get '/admin/dbbackup' do
	redirect to("/no_access") if not is_administrator?
  bdate  = Time.now()
  filename = "./tmp/master" + "-" + (bdate.strftime("%Y%m%d%H%M%S") +".bak")
	FileUtils::copy_file("./db/master.db", filename)
  if not File.zero?(filename)
    	send_file filename, :filename => "#{filename}", :type => 'Application/octet-stream'
  else
    	"No copy of the database is available. Please try again."
    	sleep(5)
    	redirect to("/admin/")
	end
end

#create backup of all attachments
get '/admin/attacments_backup' do
  bdate  = Time.now()
  zip_file = "./tmp/Attachments" + "-" + (bdate.strftime("%Y%m%d%H%M%S") +".zip")
  Zip::File.open(zip_file, Zip::File::CREATE) do |zipfile|
    Dir["./attachments/*" ].each do | name|
      zipfile.add(name.split("/").last,name)
    end
  end
  send_file zip_file, :type => 'zip', :filename => zip_file
  #File.delete(rand_zip) should the temp file be deleted?
end

# Create a new user
post '/admin/add_user' do
    redirect to("/no_access") if not is_administrator?

    user = User.first(:username => params[:username])

    if user
        if params[:password] and params[:password].size > 1
            # we have to hardcode the input params to prevent param pollution
            user.update(:type => params[:type], :auth_type => params[:auth_type], :password => params[:password])
        else
            # we have to hardcode the params to prevent param pollution
            user.update(:type => params[:type], :auth_type => params[:auth_type])
        end
    else
        user = User.new
        user.username = params[:username]
        user.password = params[:password]
        user.type = params[:type]
        user.auth_type = params[:auth_type]
        user.save
    end

    serpico_log("User #{user.username} created")
    redirect to('/admin/list_user')
end

get '/admin/list_user' do
    redirect to("/no_access") if not is_administrator?
    @admin = true
    @users = User.all
    @plugin = is_plugin?

    haml :list_user, :encode_html => true
end

get '/admin/edit_user/:id' do
    redirect to("/no_access") if not is_administrator?

    @user = User.first(:id => params[:id])

    haml :add_user, :encode_html => true
end

get '/admin/delete/:id' do
    redirect to("/no_access") if not is_administrator?

    @user = User.first(:id => params[:id])
    @user.destroy if @user

    serpico_log("User #{@user.username} deleted")

    redirect to('/admin/list_user')
end

get '/admin/add_user/:id' do
    if not is_administrator?
        id = params[:id]
        unless get_report(id)
            redirect to("/no_access")
        end
    end

    @users = User.all(:order => [:username.asc])
    @report = Reports.first(:id => params[:id])

    if is_administrator?
      @admin = true
    end

    haml :add_user_report, :encode_html => true
end

post '/admin/add_user/:id' do
    if not is_administrator?
        id = params[:id]
        unless get_report(id)
            redirect to("/no_access")
        end
    end

    report = Reports.first(:id => params[:id])

    if report == nil
        return "No Such Report"
    end

    authors = report.authors

    if authors
        authors = authors.push(params[:author])
    else
        authors = ["#{params[:author]}"]
    end

    report.authors = authors
    report.save

    redirect to("/admin/add_user/#{params[:id]}")
end

get '/admin/del_user_report/:id/:author' do
    if not is_administrator?
        id = params[:id]
        unless get_report(id)
            redirect to("/no_access")
        end
    end

    report = Reports.first(:id => params[:id])

    if report == nil
        return "No Such Report"
    end

    authors = report.authors

    if authors
        authors = authors - ["#{params[:author]}"]
    end

    report.authors = authors
    report.save

    redirect to("/admin/add_user/#{params[:id]}")
end

get '/admin/config' do
    redirect to("/no_access") if not is_administrator?

    @config = config_options
    if config_options["cvss"]
        @scoring = "cvss"
    elsif config_options["cvssv3"]
        @scoring = "cvssv3"
    elsif config_options["dread"]
        @scoring = "dread"
    elsif config_options["riskmatrix"]
        @scoring = "riskmatrix"
    else
        @scoring = "default"
    end

    haml :config, :encode_html => true
end

post '/admin/config' do
    redirect to("/no_access") if not is_administrator?

    ft = params["finding_types"].split(",")
    udv = params["user_defined_variables"].split(",")
    rat = params["report_assessment_types"].split(",")

    config_options["finding_types"] = ft
    config_options["user_defined_variables"] = udv
    config_options["port"] = params["port"]
    config_options["report_assessment_types"] = rat
    config_options["use_ssl"] = params["use_ssl"] ? true : false
    config_options["bind_address"] = params["bind_address"]
    config_options["ldap"] = params["ldap"] ? true : false
    config_options["ldap_domain"] = params["ldap_domain"]
    config_options["ldap_dc"] = params["ldap_dc"]
    config_options["burpmap"] = params["burpmap"] ? true : false
    config_options["nessusmap"] = params["nessusmap"] ? true : false
    config_options["vulnmap"] = params["vulnmap"] ? true : false
    config_options["logo"] = params["logo"]
    config_options["auto_import"] = params["auto_import"] ? true : false
    config_options["chart"] = params["chart"] ? true : false
    config_options["threshold"] = params["threshold"]
    config_options["show_exceptions"] = params["show_exceptions"] ? true : false

    if params["risk_scoring"] == "CVSSv2"
        config_options["dread"] = false
        config_options["cvss"] = true
        config_options["cvssv3"] = false
        config_options["riskmatrix"] = false
    elsif params["risk_scoring"] == "CVSSv3"
        config_options["dread"] = false
        config_options["cvss"] = false
        config_options["cvssv3"] = true
        config_options["riskmatrix"] = false
    elsif params["risk_scoring"] == "DREAD"
        config_options["dread"] = true
        config_options["cvss"] = false
        config_options["cvssv3"] = false
        config_options["riskmatrix"] = false
    elsif params["risk_scoring"] == "RISKMATRIX"
    	config_options["dread"] = false
        config_options["cvss"] = false
        config_options["cvssv3"] = false
        config_options["riskmatrix"] = true
    else
        config_options["dread"] = false
        config_options["cvss"] = false
        config_options["cvssv3"] = false
        config_options["riskmatrix"] = false
    end

    File.open("./config.json","w") do |f|
      f.write(JSON.pretty_generate(config_options))
    end
    redirect to("/admin/config")
end

# get plugins available
get '/admin/plugins' do
    redirect to("/no_access") if not is_administrator?

    @plugins = []
    Dir[File.join(File.dirname(__FILE__), "../plugins/**/", "*.json")].each { |lib|
        @plugins.push(JSON.parse(File.open(lib).read))
    }

    @admin = true if is_administrator?
    @plugin = true if is_plugin?

    haml :plugins, :encode_html => true
end

# enable plugins
post '/admin/plugins' do
    redirect to("/no_access") if not is_administrator?

    @plugins = []
    Dir[File.join(File.dirname(__FILE__), "../plugins/**/", "*.json")].each { |lib|
        @plugins.push(JSON.parse(File.open(lib).read))
    }

    @plugins.each do |plug|
        p params
        if params[plug["name"]]
            plug["enabled"] = true
            File.open("./plugins/#{plug['name']}/plugin.json","w") do |f|
              f.write(JSON.pretty_generate(plug))
            end
        else
            plug["enabled"] = false
            File.open("./plugins/#{plug['name']}/plugin.json","w") do |f|
              f.write(JSON.pretty_generate(plug))
            end
        end
    end

    redirect to("/admin/plugins")
end

# upload plugin zip
post '/admin/plugin_upload' do
    redirect to("/no_access") if not is_administrator?
    redirect to("/no_access") if not is_plugin?

    # take each zip in turn
    params['files'].map{ |upf|
        # We use a random filename
        rand_file = "./tmp/#{rand(36**36).to_s(36)}"

        # reject if the file is above a certain limit
        if upf[:tempfile].size > 100000000
            return "File too large. 100MB limit"
        end

        # unzip the plugin and write it to the fs, writing the OS is possible but so is RCE
        File.open(rand_file, 'wb') {|f| f.write(upf[:tempfile].read) }

        # find the config.json file
        config = ""
        Zip::File.open(rand_file) do |zipfile|
            # read the config file
            zipfile.each do |entry|
                if entry.name == "plugin.json"
                    configj = entry.get_input_stream.read
                    config = JSON.parse(configj)
                end
            end
        end
        if config == ""
            return "plugin.json does not exist in zip."
        end

        Zip::File.open(rand_file) do |zipfile|
            # read the config file
            zipfile.each do |entry|
                # Extract to file/directory/symlink
                fn = "./plugins/#{config['name']}/"+entry.name

                # create the directory if dne
                dirj = fn.split("/")
                dirj.pop
                unless File.directory?(dirj.join("/"))
                    FileUtils.mkdir_p(dirj.join("/"))
                end

                next if fn[-1] == "/"
                # Read into memory
                content = entry.get_input_stream.read

                File.open(fn, 'a') {|f|
                    f.write(content)
                }

            end
        end
    }
    redirect to("/admin/plugins")
end

# Manage Templated Reports
get '/admin/templates' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    # Query for all Findings
    @templates = Xslt.all(:order => [:report_type.asc])

    haml :template_list, :encode_html => true
end

# Manage Templated Reports
get '/admin/templates/add' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    haml :add_template, :encode_html => true
end

# Manage Templated Reports
get '/admin/templates/:id/download' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    xslt = Xslt.first(:id => params[:id])

    send_file xslt.docx_location, :type => 'docx', :filename => "#{xslt.report_type}.docx"
end

get '/admin/delete/templates/:id' do
    redirect to("/no_access") if not is_administrator?

    @xslt = Xslt.first(:id => params[:id])

  	if @xslt
    		@xslt.components.destroy
    		@xslt.destroy
        if File.file?(@xslt.xslt_location)
    		    File.delete(@xslt.xslt_location)
        end
        if File.file?(@xslt.docx_location)
    		    File.delete(@xslt.docx_location)
        end
  	end
    redirect to('/admin/templates')
end


# Manage Templated Reports
post '/admin/templates/add' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    xslt_file = "./templates/#{rand(36**36).to_s(36)}.xslt"

    redirect to("/admin/templates/add") unless params[:file]

    # reject if the file is above a certain limit
    if params[:file][:tempfile].size > 100000000
        return "File too large. 10MB limit"
    end

    docx = "./templates/#{rand(36**36).to_s(36)}.docx"
    File.open(docx, 'wb') {|f| f.write(params[:file][:tempfile].read) }

    error = false
    detail = ""
    begin
        xslt = generate_xslt(docx)
        xslt_components = generate_xslt_components(docx)
    rescue ReportingError => detail
        error = true
    end


    if error
        "The report template you uploaded threw an error when parsing:<p><p> #{detail.errorString}"
    else

      # open up a file handle and write the attachment
      File.open(xslt_file, 'wb') {|f| f.write(xslt) }
      #extract the screenshot names from the file
      screenshot_names = xslt.scan(/\[!!(.*?)!!\]/)
      # delete the file data from the attachment
      datax = Hash.new
      # to prevent traversal we hardcode this
      datax["docx_location"] = "#{docx}"
      datax["xslt_location"] = "#{xslt_file}"
      datax["description"] = 	params[:description]
      datax["report_type"] = params[:report_type]
      datax["screenshot_names"] = screenshot_names.join(",")
      data = url_escape_hash(datax)
      data["finding_template"] = params[:finding_template] ? true : false
      data["status_template"] = params[:status_template] ? true : false

      @template = Xslt.first(:report_type => data["report_type"])

      if @template
          @template.update(:xslt_location => data["xslt_location"], :docx_location => data["docx_location"], :description => data["description"], :screenshot_names => data["screenshot_names"])
	  @template.components.destroy
      else
          @template = Xslt.new(data)
          @template.save
      end

      # create a xslt file for each component
      list_components_files = []
      xslt_components.each do |component_name, component_xslt|
          componentHash = Hash.new
          componentHash['xslt_location'] = "./templates/#{rand(36**36).to_s(36)}.xslt"
          componentHash['name'] = component_name
          componentHash['xslt'] = @template
          File.open(componentHash['xslt_location'], 'wb') {|f| f.write(component_xslt) }
          list_components_files.push(componentHash)
      end

      # insert components into the db
      list_components_files.each do |component|
          @component = Xslt_component.new(component)
          @component.save
      end
      redirect to("/admin/templates")

      haml :add_template, :encode_html => true
  end
end

# Manage Templated Reports
get '/admin/templates/:id/edit' do
    redirect to("/no_access") if not is_administrator?

    @admind = true
    @template = Xslt.first(:id => params[:id])

    haml :edit_template, :encode_html => true
end

# Manage Templated Reports
post '/admin/templates/edit' do
    redirect to("/no_access") if not is_administrator?

    @admin = true
    template = Xslt.first(:id => params[:id])

    xslt_file = template.xslt_location

    redirect to("/admin/templates/#{params[:id]}/edit") unless params[:file]

    # reject if the file is above a certain limit
    if params[:file][:tempfile].size > 100000000
        return "File too large. 10MB limit"
    end

    docx = "./templates/#{rand(36**36).to_s(36)}.docx"
    File.open(docx, 'wb') {|f| f.write(params[:file][:tempfile].read) }

    error = false
    detail = ""
    begin
	    xslt = generate_xslt(docx)
		xslt_components = generate_xslt_components(docx)
    rescue ReportingError => detail
        error = true
    end

    if error
        "The report template you uploaded threw an error when parsing:<p><p> #{detail.errorString}"
    else

    	# open up a file handle and write the attachment
	    File.open(xslt_file, 'wb') {|f| f.write(xslt) }
      #extract the screenshot names from the file
      screenshot_names = xslt.scan(/\[!!(.*?)!!]/)
	    # delete the file data from the attachment
	    datax = Hash.new
	    # to prevent traversal we hardcode this
	    datax["docx_location"] = "#{docx}"
	    datax["xslt_location"] = "#{xslt_file}"
	    datax["description"] = 	params[:description]
	    datax["report_type"] = params[:report_type]
      datax["screenshot_names"] = screenshot_names.join(",")
	    data = url_escape_hash(datax)
	    data["finding_template"] = params[:finding_template] ? true : false
	    data["status_template"] = params[:status_template] ? true : false

	    @template = Xslt.first(:report_type => data["report_type"])

	    if @template
        @template.update(:xslt_location => data["xslt_location"], :docx_location => data["docx_location"], :description => data["description"], :screenshot_names => data["screenshot_names"])
			@template.components.destroy
	    else
		    @template = Xslt.new(data)
		    @template.save
	    end

		# create a xslt file for each component
		list_components_files = []
		xslt_components.each do |component_name, component_xslt|
			componentHash = Hash.new
			componentHash['xslt_location'] = "./templates/#{rand(36**36).to_s(36)}.xslt"
			componentHash['name'] = component_name
			componentHash['xslt'] = @template
			File.open(componentHash['xslt_location'], 'wb') {|f| f.write(component_xslt) }
			list_components_files.push(componentHash)
		end

		# insert components into the db
		list_components_files.each do |component|
			@component = Xslt_component.new(component)
			@component.save
		end
	    redirect to("/admin/templates")
    end
end

# get enabled plugins
get '/admin/admin_plugins' do
    @menu = []
    Dir[File.join(File.dirname(__FILE__), "../plugins/**/", "*.json")].each { |lib|
        pl = JSON.parse(File.open(lib).read)
        a = {}
        if pl["enabled"] and pl["admin_view"]
            # add the plugin to the menu
            a["name"] = pl["name"]
            a["description"] = pl["description"]
            a["link"] = pl["link"]
            @menu.push(a)
        end
    }
    haml :enabled_plugins, :encode_html => true
end

get '/admin/udo_templates' do
    redirect to("/no_access") unless is_administrator?

# delete UDO template part
    if params[:delete]
        udo_template = UserDefinedObjectTemplates.get(params[:delete])
        if udo_template == nil
            return "UDO Template not found"
        end
        udo_template.destroy
    end
    @udos_templates = UserDefinedObjectTemplates.all
    haml :user_defined_object_templates, :encode_html => true
end

post '/admin/udo_templates' do
    redirect to("/no_access") unless is_administrator?
    data = url_escape_hash(request.POST)

# Save new UDO template part
    if data["action"] = "Save"
        new_udo_template = UserDefinedObjectTemplates.new
        new_udo_template.type = data["object_type"]
        udo_properties = {}
        #we extract the udo properties from the posted data
        data.each do |param, value|
            if param =~ /property_/
                if not value.to_s.empty?
                    udo_properties[value] = ""
                end
            end
        end
        new_udo_template.udo_properties = udo_properties.to_json
        new_udo_template.save()
    end

    @udos_templates = UserDefinedObjectTemplates.all

    haml :user_defined_object_templates, :encode_html => true
end

#edit udo template
get '/admin/udo_template/:template_id/edit' do
    redirect to("/no_access") unless is_administrator?
    @udo_to_edit = UserDefinedObjectTemplates.get(params[:template_id])
    if @udo_to_edit == nil
        return "No such UDO Template"
    end
    @udo_to_edit_properties = JSON.parse(@udo_to_edit.udo_properties)
    haml :udo_template_edit, :encode_html => true
end

post '/admin/udo_template/:template_id/edit' do
    redirect to("/no_access") unless is_administrator?
    data = url_escape_hash(request.POST)
    @udo_to_edit = UserDefinedObjectTemplates.get(params[:template_id])
    if @udo_to_edit == nil
        return "No such UDO Template"
    end
    @udo_to_edit_properties = JSON.parse(@udo_to_edit.udo_properties)


    udo_properties = {}
    #we extract the udo properties from the posted data
    data.each do |param1, value1|
        if not value1.to_s.empty?
            #we add the new properties
            if param1 =~ /prop_new_\d+/
                id = param1.split("_")[2]
                data.each do |param2, value2|
                    if param2 =~ /default_new_#{id}/
                        if not value2 =~ /\<paragraph\>/
                            udo_properties[value1] = "<paragraph>#{value2}</paragraph>"
                        else
                            udo_properties[value1] = value2
                        end
                    end
                end
            #we edit the already existing properties
            elsif param1 =~ /prop_/
                data.each do |param2, value2|
                    if param2 =~ /default_#{param1.split("_")[-1]}/
                        if not value2 =~ /\<paragraph\>/
                            udo_properties[value1] = "<paragraph>#{value2}</paragraph>"
                        else
                            udo_properties[value1] = value2
                        end
                    end
                end
            end
        end
    end
    @udo_to_edit.udo_properties = udo_properties.to_json
    @udo_to_edit.save()
    redirect to("/admin/udo_templates")
end

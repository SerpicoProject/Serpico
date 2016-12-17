require 'sinatra/base'
require 'webrick/https'
require 'openssl'
require './model/master'
require 'zip'

class Server < Sinatra::Application
    # import config options
    config_options = JSON.parse(File.read('./config.json'))

    set :config_options, config_options
    ## Global variables
    set :finding_types, config_options["finding_types"]
    set :effort, ["Quick","Planned","Involved"]
    set :assessment_types, ["External", "Internal", "Internal/External", "Wireless", "Web Application", "DoS"]
    set :status, ["EXPLOITED"]
    set :show_exceptions, config_options["show_exceptions"]

    #Set Logging
    if(config_options["log_file"] != "")
        puts "|+| Started serpico on https://"+config_options["bind_address"]+":"+config_options["port"]
        puts "|+| Logging to "+config_options["log_file"]
        log = File.new(config_options["log_file"], "a+")
        $stdout.reopen(log)
        $stderr.reopen(log)
    end

    # CVSS
    set :av, ["Local","Local Network","Network"]
    set :ac, ["High","Medium","Low"]
    set :au, ["Multiple","Single","None"]
    set :c, ["None","Partial","Complete"]
    set :i, ["None","Partial","Complete"]
    set :a, ["None","Partial","Complete"]
    set :e, ["Not Defined","Unproven Exploit Exists","Proof-of-Concept Code","Functional Exploit Exists","High"]
    set :rl, ["Not Defined","Official Fix","Temporary Fix","Workaround","Unavailable"]
    set :rc, ["Not Defined","Unconfirmed","Uncorroborated","Confirmed"]
    set :cdp, ["Not Defined","None","Low","Low-Medium","Medium-High","High"]
    set :td, ["Not Defined","None","Low","Medium","High"]
    set :cr, ["Not Defined","Low","Medium","High"]
    set :ir, ["Not Defined","Low","Medium","High"]
    set :ar, ["Not Defined","Low","Medium","High"]

    ## LDAP Settings
    if config_options["ldap"] == "true"
        set :ldap, true
    else
        set :ldap, false
    end
    set :domain, config_options["ldap_domain"]
    set :dc, config_options["ldap_dc"]

    enable :sessions
    set :session_secret, rand(36**12).to_s(36)

    # load the default stuff
 	Dir[File.join(File.dirname(__FILE__), "routes", "*.rb")].each { |lib| require lib }
 	Dir[File.join(File.dirname(__FILE__), "helpers", "*.rb")].each { |lib| require lib }
 	Dir[File.join(File.dirname(__FILE__), "lib", "*.rb")].each { |lib| require lib }

    # load plugins last, enables monkey patching
    Dir[File.join(File.dirname(__FILE__), "plugins/**/", "*.json")].each { |lib|
        pl = JSON.parse(File.open(lib).read)
        if pl["enabled"]
            puts "|+| Loaded plugin #{pl['name']}"
            # load the plugin
            Dir[File.join(File.dirname(__FILE__), "plugins/#{pl['name']}/**/", "*.rb")].each{ |xlibx|
                require xlibx
            }
        end
    }
end

# Helper Functions
# msfrpc handler
def msfrpc(report_id)
    @msfoptions = RemoteEndpoints.first(:report_id => report_id)

    opts = {
        :host => @msfoptions.ip,
        :port => @msfoptions.port,
        :user => @msfoptions.user,
        :pass => @msfoptions.pass
    }
    begin
      rpc = Msf::RPC::Client.new(opts)
    rescue Exception => log
      puts "[!] MSF CONNECTION FAILED"
      puts log.message
      rpc = false
    end
    return rpc
end

# Return if the user has a valid session or not
def valid_session?
    return Sessions.is_valid?(session[:session_id])
end

# Get the current users type
def user_type
    return Sessions.type(session[:session_id])
end

# Get the current users, username
def get_username
    return Sessions.get_username(session[:session_id])
end

# Check if the user is an administrator
def is_administrator?
    return true if Sessions.type(session[:session_id]) == "Administrator"
end

# Check if the user has plugin upload capability
def is_plugin?
    return true if (Sessions.type(session[:session_id]) == "Administrator" and Sessions.is_plugin?(session[:session_id]) == true)
end

# authentication method used by API, returns Session Key
def auth(username,password)
    user = User.first(:username => username)

    if user and user.auth_type == "Local"
        usern = User.authenticate(username,password)

        if usern
            # TODO : This needs an expiration, session fixation
            @del_session = Sessions.first(:username => "#{usern}")
            @del_session.destroy if @del_session
            @curr_session = Sessions.create(:username => "#{usern}",:session_key => "#{session[:session_id]}")
            @curr_session.save
            return @curr_session.session_key
        end
    elsif user
        if options.ldap
            #try AD authentication
            usern = username
            if usern == "" or password == ""
                return ""
            end

            user = "#{options.domain}\\#{username}"
            ldap = Net::LDAP.new :host => "#{options.dc}", :port => 636, :encryption => :simple_tls, :auth => {:method => :simple, :username => user, :password => password}

            if ldap.bind
               # replace the session in the session table
               @del_session = Sessions.first(:username => "#{usern}")
               @del_session.destroy if @del_session
               @curr_session = Sessions.create(:username => "#{usern}",:session_key => "#{session[:session_id]}")
               @curr_session.save
               return @curr_session.session_key
            end
        end
    end
    return ""
end


# Grab a specific report
def get_report(id)
    if is_administrator?
        return Reports.first(:id => id)
    else
        report = Reports.first(:id => id)
        if report
            authors = report.authors
            return report if report.owner == get_username
            if authors
                return report if authors.include?(get_username)
            end
        end
    end
end

# List out the reports
def get_reports
    if is_administrator?
        return Reports.all( :order => [:id.desc])
    else
        reports = Reports.all( :order => [:id.desc])
        reports_array = []
        reports.each do |report|
            next unless report and get_username
            authors = report.authors
            reports_array.push(report) if report.owner == get_username
            if authors
                reports_array.push(report) if authors.include?(get_username)
            end
        end
        return nil unless reports_array
        return reports_array
    end
end

def image_insert(docx, rand_file, image, end_xml)
    # assign random id, ms requires it begin with a letter. weird.
    p_id = "d#{rand(36**7).to_s(36)}"
    name = image.description

    # insert picture into xml
    docx << " <w:pict><v:shape id=\"myShape_#{p_id}\" type=\"#_x0000_t75\" style=\"width:400; height:200\"><v:imagedata r:id=\"#{p_id}\"/></v:shape></w:pict>"
    docx << end_xml

    # insert picture into zip
    exists = false
    img_data = ""

    File.open(image.filename_location, 'rb') {|file| img_data << file.read }
    Zip::File.open(rand_file) do |zipfile|
        #iterate zipfile to see if it has media dir, this could be better
        zipfile.each do |file|
            if file.name =~ /word\/media/
                exists = true
            end
        end

        if exists
            zipfile.get_output_stream("word/media/#{name}") {|f| f.write(img_data)}
        else
            zipfile.get_output_stream("word/#{name}") {|f| f.write(img_data)}
        end
    end

    # update document.xml.rels
    docu_rels = read_rels(rand_file,"word/_rels/document.xml.rels")

    if exists
        docu_rels = docu_rels.sub("</Relationships>","<Relationship Id=\"#{p_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/#{name}\"/></Relationships>")
    else
        docu_rels = docu_rels.sub("</Relationships>","<Relationship Id=\"#{p_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"#{name}\"/></Relationships>")
    end

    docx_modify(rand_file,docu_rels,"word/_rels/document.xml.rels")

    return docx
end

# Check if the user is an administrator
def get_plugins()
    return plugins
end

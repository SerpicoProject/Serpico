require 'sinatra/base'
require 'webrick/https'
require 'openssl'
require './model/master'
require './helpers/image.rb'
require './helpers/helper.rb'
require 'zip'
require 'net/ldap'
require './config'

class Server < Sinatra::Application
  # import config options

  set :config_options, Config
  ## Global variables
  set :finding_types, Config['finding_types']
  set :finding_states, Config['finding_states']
  set :assessment_types, ['External', 'Internal', 'Internal/External', 'Wireless', 'Web Application', 'DoS']
  set :status, ['EXPLOITED']
  set :show_exceptions, Config['show_exceptions']

  if Config['effort']
    set :effort, Config['effort']
  else
    set :effort, %w[Quick Planned Involved]
  end

  if Config['show_exceptions'].to_s.casecmp('false').zero? || !(Config['show_exceptions'])
    configure do
      disable :logging
      set :set_logging, nil
      set :logging, nil
      set :logger, nil
      set :logger_out, nil
    end

    server_log('Using Serpico only logging ..')
  end

  # Set Logging
  if Config['log_file'] != ''
    log = File.new(Config['log_file'], 'a+')
    set :logger_out, log
    server_log("Logging set to #{Config['log_file']}")
  end

  # Set Alignment
  if Config['image_align'] == ''
    set :alignment, 'center'
  else
    set :alignment, Config['image_align']
  end

  # CVSS
  set :av, ['Local', 'Adjacent Network', 'Network']
  set :ac, %w[High Medium Low]
  set :au, %w[Multiple Single None]
  set :c, %w[None Partial Complete]
  set :i, %w[None Partial Complete]
  set :a, %w[None Partial Complete]
  set :e, ['Not Defined', 'Unproven Exploit Exists', 'Proof-of-Concept Code', 'Functional Exploit Exists', 'High']
  set :rl, ['Not Defined', 'Official Fix', 'Temporary Fix', 'Workaround', 'Unavailable']
  set :rc, ['Not Defined', 'Unconfirmed', 'Uncorroborated', 'Confirmed']
  set :cdp, ['Not Defined', 'None', 'Low', 'Low-Medium', 'Medium-High', 'High']
  set :td, ['Not Defined', 'None', 'Low', 'Medium', 'High']
  set :cr, ['Not Defined', 'Low', 'Medium', 'High']
  set :ir, ['Not Defined', 'Low', 'Medium', 'High']
  set :ar, ['Not Defined', 'Low', 'Medium', 'High']

  set :attack_vector, %w[Local Adjacent Network Physical]
  set :attack_complexity, %w[Low High]
  set :privileges_required, %w[None Low High]
  set :user_interaction, %w[None Required]
  set :scope_cvss, %w[Unchanged Changed]
  set :confidentiality, %w[None Low High]
  set :integrity, %w[None Low High]
  set :availability, %w[None Low High]
  set :exploit_maturity, ['Not Defined', 'Unproven Exploit Exists', 'Proof-of-Concept Code', 'Functional Exploit Exists', 'High']
  set :remeditation_level, ['Not Defined', 'Official Fix', 'Temporary Fix', 'Workaround', 'Unavailable']
  set :report_confidence, ['Not Defined', 'Unknown', 'Reasonable', 'Confirmed']
  set :confidentiality_requirement, ['Not Defined', 'Low', 'Medium', 'High']
  set :integrity_requirement, ['Not Defined', 'Low', 'Medium', 'High']
  set :availability_requirement, ['Not Defined', 'Low', 'Medium', 'High']
  set :mod_attack_vector, ['Not Defined', 'Local', 'Adjacent', 'Network', 'Physical']
  set :mod_attack_complexity, ['Not Defined', 'Low', 'High']
  set :mod_privileges_required, ['Not Defined', 'None', 'Low', 'High']
  set :mod_user_interaction, ['Not Defined', 'None', 'Required']
  set :mod_scope, ['Not Defined', 'Unchanged', 'Changed']
  set :mod_confidentiality, ['Not Defined', 'None', 'Low', 'High']
  set :mod_integrity, ['Not Defined', 'None', 'Low', 'High']
  set :mod_availability, ['Not Defined', 'None', 'Low', 'High']

  # Risk Matrix
  set :severity, %w[Low Medium High]
  set :likelihood, %w[Low Medium High]

  # NIST800
  set :nist_likelihood, ['Low','Moderate','High']
  set :nist_impact, ['Informational','Low','Moderate','High','Critical']

  if Config['cvssv2_scoring_override']
    if Config['cvssv2_scoring_override'] == 'true'
      set :cvssv2_scoring_override, true
    end
  else
    set :cvssv2_scoring_override, false
  end

  ## LDAP Settings
  if Config['ldap'] == 'true'
    set :ldap, true
  else
    set :ldap, false
  end
  set :domain, Config['ldap_domain']
  set :dc, Config['ldap_dc']

  enable :sessions
  set :session_secret, rand(36**12).to_s(36)

  # load the default stuff
  Dir[File.join(File.dirname(__FILE__), 'routes', '*.rb')].each { |lib| require lib }
  Dir[File.join(File.dirname(__FILE__), 'helpers', '*.rb')].each { |lib| require lib }
  Dir[File.join(File.dirname(__FILE__), 'lib', '*.rb')].each { |lib| require lib }

  # load plugins last, enables monkey patching
  Dir[File.join(File.dirname(__FILE__), 'plugins/**/', '*.json')].each do |lib|
    pl = JSON.parse(File.open(lib).read)
    next unless pl['enabled']
    server_log("Loaded plugin #{pl['name']}")
    # load the plugin
    Dir[File.join(File.dirname(__FILE__), "plugins/#{pl['name']}/**/", '*.rb')].each do |xlibx|
      require xlibx
    end
  end
end

# Helper Functions
# msfrpc handler
def msfrpc(report_id)
  @msfoptions = RemoteEndpoints.first(report_id: report_id)

  opts = {
    host: @msfoptions.ip,
    port: @msfoptions.port,
    user: @msfoptions.user,
    pass: @msfoptions.pass
  }
  begin
    rpc = Msf::RPC::Client.new(opts)
  rescue Exception => log
    server_log('[!] MSF CONNECTION FAILED')
    rpc = false
  end
  rpc
end

# Return if the user has a valid session or not
def valid_session?
  Sessions.is_valid?(session[:session_id])
end

# Get the current users type
def user_type
  Sessions.type(session[:session_id])
end

# Get the current users, username
def get_username
  Sessions.get_username(session[:session_id])
end

# Check if the user is an administrator
def is_administrator?
  return true if Sessions.type(session[:session_id]) == 'Administrator'
end

# Check if the user has plugin upload capability
def is_plugin?
  return true if (Sessions.type(session[:session_id]) == 'Administrator') && (Sessions.is_plugin?(session[:session_id]) == true)
end

# authentication method used by API, returns Session Key
def auth(username, password)
  user = User.first(username: username)

  if user && (user.auth_type == 'Local')
    usern = User.authenticate(username, password)

    if usern
      # TODO : This needs an expiration, session fixation
      @del_session = Sessions.first(username: usern.to_s)
      @del_session.destroy if @del_session
      @curr_session = Sessions.create(username: usern.to_s, session_key: session[:session_id].to_s)
      @curr_session.save
      return @curr_session.session_key
    end
  elsif user
    if options.ldap
      # try AD authentication
      usern = username
      return '' if (usern == '') || (password == '')

      user = "#{options.domain}\\#{username}"
      ldap = Net::LDAP.new host: options.dc.to_s, port: 636, encryption: :simple_tls, auth: { method: :simple, username: user, password: password }

      if ldap.bind
        # replace the session in the session table
        @del_session = Sessions.first(username: usern.to_s)
        @del_session.destroy if @del_session
        @curr_session = Sessions.create(username: usern.to_s, session_key: session[:session_id].to_s)
        @curr_session.save
        return @curr_session.session_key
      else
        server_log('|!| LDAP Authentication failed')
      end
    end
  end
  ''
end

# Grab a specific report
def get_report(id)
  if is_administrator?
    return Reports.first(id: id)
  else
    report = Reports.first(id: id)
    if report
      authors = report.authors
      return report if report.owner == get_username
      if authors
        return report if authors.include?(get_username)
      end
    end
  end
rescue Exception => log
  # ignoring this error for now
end

# List out the reports
def get_reports
  if is_administrator?
    return Reports.all(order: [:id.desc])
  else
    reports = Reports.all(order: [:id.desc])
    reports_array = []
    reports.each do |report|
      next unless report && get_username
      authors = report.authors
      reports_array.push(report) if report.owner == get_username
      if authors
        reports_array.push(report) if authors.include?(get_username)
      end
    end
    return nil unless reports_array
    return reports_array
  end
rescue Exception
  return []
end

def image_insert(docx, rand_file, image, end_xml)
  # assign random id, ms requires it begin with a letter. weird.
  p_id = "d#{rand(36**7).to_s(36)}"
  name = image.description

  image_file = File.open(image.filename_location, 'rb')
  img_data = image_file.read

  # resize picture to fit into word if it's too big
  if jpeg?(img_data)
    jpeg_dimension = JPEG.new(image.filename_location)
    width = jpeg_dimension.width
    height = jpeg_dimension.height
  elsif png?(img_data)
    width = IO.read(image.filename_location)[0x10..0x18].unpack('NN')[0]
    height = IO.read(image.filename_location)[0x10..0x18].unpack('NN')[1]
  # we don't want to break everything if another format is supported
  else
    width = 400
    height = 200
  end
  while (width > 710) || (height > 790) # fits nicely into word
    width -= (width / 20)
    height -= (height / 20)
  end
  image_file.close

  # Image alignment setting
  settings.alignment = 'center' unless settings.alignment

  imgAlign = case settings.alignment.downcase
             when 'Left'
               'left'
             when 'Right'
               'right'
             when 'Center'
               'center'
             else
               'center'
             end

  # insert picture into xml, allow the user to ignore alignment if they want
  if settings.alignment == 'ignore'
    docx << "<w:pict><v:shape id=\"myShape_#{p_id}\" type=\"#_x0000_t75\" style=\"width:#{width}; height:#{height}\"><v:imagedata r:id=\"#{p_id}\"/></v:shape></w:pict>"
  else
    docx << "<w:p><w:pPr><w:jc w:val=\"#{imgAlign}\"/></w:pPr><w:pict><v:shape id=\"myShape_#{p_id}\" type=\"#_x0000_t75\" style=\"width:#{width}; height:#{height}\"><v:imagedata r:id=\"#{p_id}\"/></v:shape></w:pict></w:p>"
  end
  docx << end_xml

  # insert picture into zip
  exists = false

  Zip::File.open(rand_file) do |zipfile|
    # iterate zipfile to see if it has media dir, this could be better
    zipfile.each do |file|
      exists = true if file.name =~ /word\/media/
    end

    if exists
      zipfile.get_output_stream("word/media/#{name}") { |f| f.write(img_data) }
    else
      zipfile.get_output_stream("word/#{name}") { |f| f.write(img_data) }
    end
  end

  # update document.xml.rels
  docu_rels = read_rels(rand_file, 'word/_rels/document.xml.rels')

  if exists
    docu_rels = docu_rels.sub('</Relationships>', "<Relationship Id=\"#{p_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/#{name}\"/></Relationships>")
  else
    docu_rels = docu_rels.sub('</Relationships>', "<Relationship Id=\"#{p_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"#{name}\"/></Relationships>")
  end

  docx_modify(rand_file, docu_rels, 'word/_rels/document.xml.rels')

  docx
end

def get_plugin_list(type)
  menu = []

  Dir[File.join(File.dirname(__FILE__), 'plugins/**/', '*.json')].each do |lib|
    pl = JSON.parse(File.open(lib).read)
    next if not pl['enabled']
    a = {}
    if type == 'user'
       next if not pl['report_view']
    elsif type == 'admin'
      next if not pl['admin_view']
    end
    # add the plugin to the menu
    a['name'] = pl['name']
    a['description'] = pl['description']
    a['link'] = pl['link']
    menu.push(a)
  end
  menu
end

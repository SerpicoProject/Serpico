require 'sinatra'
require 'odle'

#####
# Reporting Routes
#####

config_options = JSON.parse(File.read('./config.json'))

# set the report_assessment_types for <1.2 versions of Serpico
unless config_options['report_assessment_types']
  config_options['report_assessment_types'] = ['Network Internal', 'External', 'Web application', 'Physical', 'Social engineering', 'Configuration audit']
end

# List current reports
get '/reports/list' do
  @reports = get_reports

  @admin = true if is_administrator?

  # allow the user to set their logo in the configuration options
  @logo = config_options['logo']

  haml :reports_list
end

# Create a report
get '/report/new' do
  @templates = Xslt.all
  @assessment_types = config_options['report_assessment_types']
  @languages = config_options['languages']

  @admin = true if is_administrator?
  @plugin = true if is_plugin?

  haml :new_report
end

# Create a report
post '/report/new' do
  data = url_escape_hash(request.POST)

  data['owner'] = get_username
  data['date'] = DateTime.now.strftime '%m/%d/%Y'

  @report = Reports.new(data)
  @report.scoring = set_scoring(config_options)
  @report.save

  # compensate for datamappers oddness
  @report1 = get_report(@report.id)

  redirect to("/report/#{@report.id}/edit")
end

# List attachments and provides an overview on uploaded screenshots
get '/report/:id/attachments' do
  id = params[:id]

  # Query for the first report matching the id
  @report = get_report(id)
  return 'No Such Report' if @report.nil?
  @screenshot_names_from_findings = {}
  # fetching screenshots names in findings
  findings = Findings.all(report_id: id)

  findings.each do |find|
    next unless find.overview or find.poc or find.remediation or find.notes

    text = ""
    if find.overview
      text = text + find.overview
    end
    if find.poc
      text = text + find.poc
    end
    if find.remediation
      text = text + find.remediation
    end
    if find.notes
      text = text + find.notes
    end

    @screenshot_names_from_findings[find.id] = []
    # for each finding, we extract the screenshot name in the poc field.
    # screenshot names are like this : [!!screenshotnames.png!!]
    text.to_s.split('<paragraph>').each do |pp|
      next unless pp =~ /\[\!\!/
      @screenshot_names_from_findings[find.id] << pp.split('[!!')[1].split('!!]').first
    end
  end
  @attachments = Attachments.all(report_id: id)
  # fetching screenshot names in report
  xslt = Xslt.first(report_type: @report.report_type)
  @screenshot_names_from_report = xslt.screenshot_names
  @screenshot_names_from_findings
  haml :list_attachments
end

get '/report/:id/export_attachments' do
  id = params[:id]
  rand_zip = "./tmp/#{rand(36**12).to_s(36)}.zip"
  @attachments = Attachments.all(report_id: id)

  Zip::File.open(rand_zip, Zip::File::CREATE) do |zipfile|
    @attachments.each do |attachment|
      zipfile.add(attachment.filename_location.gsub('./attachments/', ''), attachment.filename_location)
    end
  end

  send_file rand_zip, type: 'zip', filename: 'attachments.zip'
  # File.delete(rand_zip) should the temp file be deleted?
end

# Restore Attachments menu
get '/report/:id/restore_attachments' do
  @id = params[:id]
  @report = get_report(@id)
  return 'No Such Report' if @report.nil?

  haml :restore_attachments
end

post '/report/:id/restore_attachments' do
  id = params['id']
  # Not sure this is the best way to do this.
  rand_zip = "./tmp/#{rand(36**12).to_s(36)}.zip"
  File.open(rand_zip, 'wb') { |f| f.write(params[:file][:tempfile].read) }
  begin
    Zip::File.open(rand_zip) do |file|
      n = file.num_files
      n.times do |i|
        entry_name = file.get_name(i)
        file.fopen(entry_name) do |f|
          clean_name = f.name.split('.')[0]
          File.open("./attachments/#{clean_name}", 'wb') do |data|
            data << f.read
          end
        end
      end
    end
  rescue
    puts 'Not a Zip file. Please try again'
  end
  # File.delete(rand_zip) should the temp file be deleted?
  redirect to("/report/#{id}/edit")
end

# Odle based scan import
get '/report/:id/import_scan_data' do
  id = params[:id]

  # Query for the first report matching the id
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  @auto_import = config_options['auto_import']
  haml :import_scan_data
end

post '/report/:id/import_scan_data' do
  type = params[:type].to_s.downcase

  scan_xml = params[:file][:tempfile].read

  id = params[:id]

  # verify access to the report
  @report = get_report(id)
  return 'No Such Report' if @report.nil?

  if type == 'nessus'
    data = JSON.parse(Nessus.new.parse(scan_xml, config_options['threshold']))
  elsif type == 'burpv1'
    data = JSON.parse(Burp.new.parse(scan_xml, config_options['threshold']))
  elsif type == 'metasploit'
    data = JSON.parse(Metasploit.new.parse(scan_xml, config_options['threshold']))
  elsif type == 'nmap'
    data = JSON.parse(Nmap.new.parse(scan_xml, config_options['threshold']))
  else
    "Unknown type: #{type}"
  end

  vulns = import_odle(data)['findings']
  return 'Data import failed or 0 findings in import file' unless vulns

  vulns.each do |vuln|
      vuln.report_id = id
      vuln.save
  end

  # go directly to findings list menu
  @total_added = vulns.size
  @chart = config_options['chart']
  @plugin_side_menu = get_plugin_list('user')
  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)
  @cvssv2_scoring_override = if config_options.key?('cvssv2_scoring_override')
                               config_options['cvssv2_scoring_override']
                             else
                               false
                             end

  haml :findings_list
end

# upload nessus xml files to be processed
get '/report/:id/import_nessus' do
  id = params[:id]

  @nessusmap = config_options['nessusmap']

  # Query for the first report matching the id
  @report = get_report(id)

  haml :import_nessus
end

# auto add serpico findings if mapped to nessus ids
post '/report/:id/import_autoadd' do
  type = params[:type]

  xml = params[:file][:tempfile].read
  if xml =~ /^<NessusClientData_v2>/ && type == 'nessus'
    import_nessus = true
    vulns = parse_nessus_xml(xml, config_options['threshold'])
  elsif xml =~ /^<issues burpVersion/ && type == 'burp'
    import_burp = true
    vulns = parse_burp_xml(xml)
  else
    return 'File does not contain valid XML import data'
  end

  # reject if the file is above a certain limit
  # if params[:file][:tempfile].size > 1000000
  #        return "File too large. 1MB limit"
  # end
  # Check for kosher name in report name
  id = params[:id]

  add_findings = []
  dup_findings = []
  autoadd_hosts = {}

  # Query for the first report matching the report_name
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  # load all findings
  @findings = TemplateFindings.all(order: [:title.asc])

  # parse nessus xml into hash
  # nessus_vulns = parse_nessus_xml(nessus_xml)

  # determine findings to add from vuln data
  # host/ip is key, value is array of vuln ids
  vulns.keys.each do |i|
    vulns[i].each do |v|
      # if serpico finding id maps to nessus/burp plugin id, add to report
      if import_nessus
        @mappings = NessusMapping.all(pluginid: v)
      elsif import_burp
        @mappings = BurpMapping.all(pluginid: v)
      end

      # add affected hosts for each finding
      next unless @mappings
      @mappings.each do |m|
        if autoadd_hosts[m.templatefindings_id]
          # only one host/url per finding (regardless of ports and urls). this should change in the future
          unless autoadd_hosts[m.templatefindings_id].include?(i)
            autoadd_hosts[m.templatefindings_id] << i
          end
        else
          autoadd_hosts[m.templatefindings_id] = []
          autoadd_hosts[m.templatefindings_id] << i
        end
        add_findings << m.templatefindings_id
      end
    end
  end

  add_findings = add_findings.uniq

  # create new findings from an import
  # TODO: This will duplicate if the user already has a nessus id mapped
  if config_options['auto_import']
    vulns['findings'].each do |vuln|
      vuln.report_id = id
      vuln.save
    end
  end

  if add_findings.empty?
    redirect to("/report/#{id}/findings")
  else
    @autoadd = true

    add_findings.each do |finding|
      # if the finding already exists in the report dont add
      currentfindings = Findings.all(report_id: id)
      currentfindings.each do |cf|
        next unless cf.master_id == finding.to_i
        dup_findings << finding.to_i unless dup_findings.include?(finding.to_i)
        add_findings.delete(finding.to_i)
      end
    end
    @autoadd_hosts = autoadd_hosts
    @dup_findings = dup_findings.uniq
    @autoadd_findings = add_findings
  end
  haml :findings_add
end

# upload burp xml files to be processed
get '/report/:id/import_burp' do
  id = params[:id]

  @burpmap = config_options['burpmap']

  # Query for the first report matching the id
  @report = get_report(id)

  haml :import_burp
end

# Upload attachment menu
get '/report/:id/upload_attachments' do
  id = params[:id]
  @no_file = params[:no_file]

  # Query for the first report matching the id
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  @attachments = Attachments.all(report_id: id)
  haml :upload_attachments
end

post '/report/:id/upload_attachments' do
  id = params[:id]

  # Query for the first report matching the id
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  if params[:files].nil?
    redirect to("/report/#{id}/upload_attachments?no_file=1")
  end

  params['files'].map do |upf|
    # We use a random filename
    rand_file = "./attachments/#{rand(36**36).to_s(36)}"

    # reject if the file is above a certain limit
    return 'File too large. 100MB limit' if upf[:tempfile].size > 100_000_000

    # open up a file handle and write the attachment
    File.open(rand_file, 'wb') { |f| f.write(upf[:tempfile].read) }

    # delete the file data from the attachment
    datax = {}
    # to prevent traversal we hardcode this
    datax['filename_location'] = rand_file.to_s
    datax['filename'] = upf[:filename]
    datax['description'] = CGI.escapeHTML(upf[:filename]).tr(' ', '_').tr('/', '_').tr('\\', '_').tr('`', '_')
    datax['report_id'] = id
    datax['appendice'] = params[:appendice]
    data = url_escape_hash(datax)

    @attachment = Attachments.new(data)
    @attachment.save
  end
  redirect to("/report/#{id}/attachments")
end

get '/report/:id/export_attachments' do
  id = params[:id]
  rand_zip = "./tmp/#{rand(36**12).to_s(36)}.zip"
  @attachments = Attachments.all(report_id: id)

  Zip::File.open(rand_zip, Zip::File::CREATE) do |zipfile|
    @attachments.each do |attachment|
      zipfile.add(attachment.filename_location.gsub('./attachments/', ''), attachment.filename_location)
    end
  end

  send_file rand_zip, type: 'zip', filename: 'attachments.zip'
  # File.delete(rand_zip) should the temp file be deleted?
end

# display attachment
get '/report/:id/attachments/:att_id' do
  id = params[:id]

  # Query for the first report matching the id
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  @attachment = Attachments.first(report_id: id, id: params[:att_id])
  send_file @attachment.filename_location, filename: @attachment.filename.to_s
end

# Delete an attachment
get '/report/:id/attachments/delete/:att_id' do
  id = params[:id]

  # Query for the first report matching the id
  @report = get_report(id)

  return 'No Such Report' if @report.nil?
  params[:att_id].split(',').each do |current_id|
    @attachment = Attachments.first(report_id: id, id: current_id)
    return "No Such Attachment : #{current_id}" if @attachment.nil?
    if File.file?(@attachment.filename_location)
      File.delete(@attachment.filename_location)
    end
    # delete the entries
    @attachment.destroy
  end
  redirect to("/report/#{id}/attachments")
end

# Delete a report
get '/report/remove/:id' do
  id = params[:id]
  params[:id].split(',').each do |current_id|
    report = get_report(current_id)
    return "No Such Report : #{current_id}" if report.nil?
    # get all findings and udos associated with the report
    findings = Findings.all(report_id: id)
    udos = UserDefinedObjects.all(report_id: id)

    # Notify the plugins that the report will be deleted
    PluginNotifier.instance.notify_report_deleted(report)

    # delete the entries
    findings.destroy
    udos.destroy
    report.destroy
  end
  serpico_log("Report deleted, Report #{id}")
  redirect to('/reports/list')
end

# Edit the Report's main information; Name, Consultant, etc.
get '/report/:id/edit' do
  id = params[:id]

  # Query for the first report matching the report_name
  @report = get_report(id)
  @templates = Xslt.all(order: [:report_type.asc])
  @plugin_side_menu = get_plugin_list('user')
  @assessment_types = config_options['report_assessment_types']
  @languages = config_options['languages']
  @risk_scores = %w[Risk DREAD CVSS CVSSv3 RiskMatrix NIST800]

  return 'No Such Report' if @report.nil?

  @report.update(scoring: set_scoring(config_options)) unless @report.scoring

  haml :report_edit
end

# Edit the Report's main information; Name, Consultant, etc.
get '/report/:id/additional_features' do
  id = params[:id]

  # Query for the first report matching the report_name
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  haml :additional_features
end

# Edit a report
post '/report/:id/edit' do
  id = params[:id]

  data = url_escape_hash(request.POST)
  @report = get_report(id)

  unless @report.update(data)
    error = ""
    @report.errors.each do |f|
      error = error + f.to_s() + "<br>"
    end
    return "<p>The following error(s) were found while trying to update : </p>#{error}"
  end

  redirect to("/report/#{id}/edit")
end

# Manage user defined objects. User can see all UDOs from here.
get '/report/:id/udo/manage' do
  # if a udo has just been created, we add a message
  @id = params[:id]
  @report = get_report(@id)
  return 'No Such Report' if @report.nil?

  if params[:created_id]
    @udo_template_created = UserDefinedObjectTemplates.get(params[:created_id])
  end
  @udos_templates = UserDefinedObjectTemplates.all

  haml :user_defined_object_manage
end

# Create new user defined objects. Get => the user chose the udo values
get '/report/:id/udo/:udo_template_id/create' do
  @id = params[:id]
  @report = get_report(@id)
  return 'No Such Report' if @report.nil?

  @udo_template = UserDefinedObjectTemplates.get(params[:udo_template_id])
  return 'no Such UDO Template' if @udo_template.nil?
  @udo_template_properties = JSON.parse(@udo_template.udo_properties)
  haml :user_defined_object_create
end

# Create new user defined objects. Post => the UDO is stored in database
post '/report/:id/udo/:udo_template_id/create' do
  data = url_escape_hash(request.POST)
  id = params[:id]
  report = get_report(id)
  return 'No Such Report' if report.nil?
  udo_template_id = params[:udo_template_id]
  @udo_template = UserDefinedObjectTemplates.get(udo_template_id)
  return 'no Such UDO Template' if @udo_template.nil?
  # we create the udo
  @udo = UserDefinedObjects.new
  @udo.type = @udo_template.type
  @udo.report_id = id
  @udo.template_id = udo_template_id
  # we extract the properties from the posted data
  udo_properties = {}
  data.each do |post_param, post_value|
    if post_param =~ /param_/
      if post_value !~ /\<paragraph\>/
        udo_properties[post_param.split('_')[1].downcase] = "<paragraph>#{post_value}</paragraph>"
      else
        udo_properties[post_param.split('_')[1].downcase] = post_value
      end
    end
  end
  @udo.udo_properties = udo_properties.to_json
  @udo.save
  # we go back to the manage panel after creating the udo
  redirect to("/report/#{id}/udo/manage?created_id=#{@udo_template.id}")
end

# Edit an UDO. get => user chose the values
get '/report/:id/udo/:udo_id/edit' do
  id = params[:id]
  udo_id = params[:udo_id]
  @report = get_report(id)
  return 'No Such Report' if @report.nil?

  # By asking only udos for the report we have access to, we're safe from
  # edit by arbitrary user
  udos = UserDefinedObjects.all(report_id: id, id: udo_id)
  return 'No Such UDO for this report' if udos.empty?
  @udo_to_edit = UserDefinedObjects.new
  # there will always be only one udo in this collecion
  udos.each do |udo_to_edit|
    @udo_to_edit = udo_to_edit
  end
  # udo template linked to the udo to edit. We want the template in case the admin changed the properties
  @udo_template = UserDefinedObjectTemplates.get(@udo_to_edit.template_id)
  @udo_template_properties = JSON.parse(@udo_template.udo_properties)
  @udo_to_edit_properties = JSON.parse(@udo_to_edit.udo_properties)

  haml :user_defined_object_edit
end

# Edit an UDO. Post => value stored in db
post '/report/:id/udo/:udo_id/edit' do
  data = url_escape_hash(request.POST)
  id = params[:id]
  udo_id = params[:udo_id]
  report = get_report(id)
  return 'No Such Report' if report.nil?
  # By asking only udos for the report we have access to, we're safe from
  # edit by arbitrary user
  udos = UserDefinedObjects.all(report_id: id, id: udo_id)
  return 'No Such UDO for this report' if udos.empty?
  edited_udo = UserDefinedObjects.new
  # there will always be only one udo in this collecion
  udos.each do |udo_to_edit|
    edited_udo = udo_to_edit
  end
  # we extract the properties from the posted data
  udo_new_properties = {}
  data.each do |post_param, post_value|
    if post_param =~ /param_/
      if post_value !~ /\<paragraph\>/
        udo_new_properties[post_param.split('_')[1].downcase] = "<paragraph>#{post_value}</paragraph>"
      else
        udo_new_properties[post_param.split('_')[1].downcase] = post_value
      end
    end
  end
  edited_udo.udo_properties = udo_new_properties.to_json
  edited_udo.save
  redirect to("/report/#{id}/udo/manage")
end

# Delete an UDO
get '/report/:id/udo/:udo_id/delete' do
  @id = params[:id]
  udo_id = params[:udo_id]
  report = get_report(@id)
  return 'No Such Report' if report.nil?
  # By asking only udos for the report we have access to, we're safe from
  # delete by arbitrary user
  udos = UserDefinedObjects.all(report_id: @id, id: udo_id)
  return 'No Such UDO for this report' if udos.empty?
  # there will always be only one udo in this collecion
  udos.each(&:destroy)
  redirect to("/report/#{@id}/udo/manage")
end

# Edit user defined variable
get '/report/:id/user_defined_variables' do
  id = params[:id]
  @report = get_report(id)

  if @report.user_defined_variables
    @user_variables = JSON.parse(@report.user_defined_variables)

    # add in the global UDV from config
    if !config_options['user_defined_variables'].empty? && !@user_variables.include?(config_options['user_defined_variables'][0])
      config_options['user_defined_variables'].each do |key, _value|
        @user_variables.store(key, '')
      end
    end

    @user_variables.each do |k, v|
      @user_variables[k] = meta_markup(v) if v
    end
  else
    @user_variables = config_options['user_defined_variables']
  end

  haml :user_defined_variable
end

# TODO: this route needs proper comments, it is very confusing
post '/report/:id/user_defined_variables' do
  data = url_escape_hash(request.POST)

  data.each do |k, v|
    if k =~ /variable_data/ && (v !~ /\<paragraph\>/)
      data[k.strip] = "<paragraph>#{v}</paragraph>"
    end
  end

  variable_hash = {}
  data.each do |k, v|
    if k =~ /variable_name/
      key = k.split('variable_name_').last.split('_').first.strip

      v = v.tr('%', '_').gsub('&quot;', "'").gsub('&amp;', '').gsub('&gt;', '').gsub('&lt;', '')

      variable_hash["#{key}%#{v}"] = 'DEFAULT'

    end

    # TODO are the next few lines ever hit?
    next unless k =~ /variable_data/
    key = k.split('variable_data_').last.split('_').first.strip

    variable_hash.each do |k1, _v1|
      next unless k1 =~ /%/
      kk = k1.split('%')
      variable_hash[k1] = v if kk.first == key
    end
  end

  q = variable_hash.clone
  variable_hash.each do |k, v|
    next unless k =~ /%/
    if k.split('%').size == 1
      q.delete(k)
    else
      q[k.split('%').last.strip] = v
      q.delete(k)
    end
  end
  variable_hash = q

  id = params[:id]
  @report = get_report(id)

  @report.user_defined_variables = variable_hash.to_json
  @report.save
  redirect to("/report/#{id}/user_defined_variables")
end

# Findings List Menu
get '/report/:id/findings' do
  @chart = config_options['chart']
  @report = true
  id = params[:id]

  # Query for the first report matching the report_name
  @report = get_report(id)
  @plugin_side_menu = get_plugin_list('user')

  return 'No Such Report' if @report.nil?

  @report.update(scoring: set_scoring(config_options)) unless @report.scoring

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)

  @cvssv2_scoring_override = if config_options.key?('cvssv2_scoring_override')
                               config_options['cvssv2_scoring_override']
                             else
                               false
                             end
  haml :findings_list
end

# Generate a status report from the current findings
get '/report/:id/status' do
  id = params[:id]

  # Query for the report
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)

  ## We have to do some hackery here for wordml
  findings_xml = ''
  findings_xml << '<findings_list>'
  @findings.each do |finding|
    ### Let's find the diff between the original and the new overview and remediation
    master_finding = TemplateFindings.first(id: finding.master_id)

    findings_xml << finding.to_xml
  end
  findings_xml << '</findings_list>'

  findings_xml = meta_markup_unencode(findings_xml, @report)

  report_xml = findings_xml.to_s

  xslt_elem = Xslt.first(status_template: true)

  if xslt_elem

    # Push the finding from XML to XSLT
    xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

    docx_xml = xslt.transform(Nokogiri::XML(report_xml))

    # We use a temporary file with a random name
    rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

    # Create a temporary copy of the finding_template
    FileUtils.copy_file(xslt_elem.docx_location, rand_file)

    ### IMAGE INSERT CODE
    if docx_xml.to_s =~ /\[!!/
      # first we read in the current [Content_Types.xml]
      content_types = read_rels(rand_file, '[Content_Types].xml')

      # add the png and jpg handling to end of content types document
      if content_types !~ /image\/jpg/
        content_types = content_types.sub('</Types>', '<Default Extension="jpg" ContentType="image/jpg"/></Types>')
      end
      if content_types !~ /image\/png/
        content_types = content_types.sub('</Types>', '<Default Extension="png" ContentType="image/png"/></Types>')
      end
      if content_types !~ /image\/jpeg/
        content_types = content_types.sub('</Types>', '<Default Extension="jpeg" ContentType="image/jpeg"/></Types>')
      end

      docx_modify(rand_file, content_types, '[Content_Types].xml')

      # replace all [!! image !!] in the document
      imgs = docx_xml.to_s.split('[!!')
      docx = imgs.first
      imgs.delete_at(0)

      imgs.each do |image_i|
        name = image_i.split('!!]').first.delete(' ')
        end_xml = image_i.split('!!]').last

        # search for the image in the attachments
        image = Attachments.first(description: name, report_id: id)

        # tries to prevent breakage in the case image dne
        if image
          docx = image_insert(docx, rand_file, image, end_xml)
        else
          docx = docx.sub(/<w:p[^\>]*?>((?<!<w:p[ |>]).)*\z/m, '')
          end_xml = end_xml.sub(/^<\/w:t>.*?<\/w:r>.*?<\/w:p>/m, '')
          docx << end_xml
        end
      end

    else
      # no images in finding
      docx = docx_xml.to_s
    end
    #### END IMAGE INSERT CODE

    docx_modify(rand_file, docx, 'word/document.xml')

    send_file rand_file, type: 'docx', filename: 'status.docx'

  else
    "You don't have a Finding Template (did you delete the temp?) -_- ... If you're an admin go to <a href='/admin/templates/add'>here</a> to add one."
  end
end

# Add a finding to the report
get '/report/:id/findings_add' do
  # Check for kosher name in report name
  id = params[:id]

  # Query for the first report matching the report_name
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  @languages = config_options['languages']

  # Query for all Findings
  @findings = TemplateFindings.all(approved: true, order: [:title.asc])

  haml :findings_add
end

# Add a finding to the report
post '/report/:id/findings_add' do
  # Check for kosher name in report name
  id = params[:id]

  # Query for the first report matching the report_name
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  hosts = ''

  redirect to("/report/#{id}/findings") unless params[:finding]

  params[:finding].each do |finding|
    templated_finding = TemplateFindings.first(id: finding.to_i)

    templated_finding.id = nil
    attr = templated_finding.attributes
    attr.delete(:approved)
    attr['master_id'] = finding.to_i
    @newfinding = Findings.new(attr)
    @newfinding.report_id = id

    # because of multiple scores we need to make sure all are set
    # => leave it up to the user to make the calculation if they switch mid report
    @newfinding.dread_total = 0 if @newfinding.dread_total.nil?
    @newfinding.nist800_total = 0 if @newfinding.nist800_total == nil
    @newfinding.cvss_total = 0  if @newfinding.cvss_total.nil?
    @newfinding.risk = 0 if @newfinding.risk.nil?

    @newfinding.save
  end

  # if we have hosts add them to the findings too
  params[:finding].each do |number|
    # if there are hosts to add with a finding they'll have a param syntax of "findingXXX=ip1,ip2,ip3"
    @findingnum = "finding#{number}"
    # TODO: merge with existing hosts (if any) probably should handle this host stuff in the db
    finding = Findings.first(report_id: id, master_id: number.to_i)

    unless params[@findingnum.to_s].nil?
      params[@findingnum.to_s].split(',').each do |ip|
        # TODO: this is dirty. also should support different delimeters instead of just newline
        hosts << '<paragraph>' + ip.to_s + '</paragraph>'
      end

      finding.affected_hosts = hosts
      hosts = ''
    end
    finding.save
  end

  serpico_log("#{@newfinding.title} added to report #{id}")

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)

  haml :findings_list
end

# Create a new finding in the report
get '/report/:id/findings/new' do
  # Query for the first report matching the report_name
  @report = get_report(params[:id])
  return 'No Such Report' if @report.nil?

  # attachments autocomplete work
  temp_attaches = Attachments.all(report_id: params[:id])
  @attaches = []
  temp_attaches.each do |ta|
    next unless ta.description =~ /\.png$/i || ta.description =~ /\.jpg$/i || ta.description =~ /\.jpeg$/i
    @attaches.push(ta.description)
  end

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)

  haml :create_finding
end

# Create the finding in the DB
post '/report/:id/findings/new' do
  error = mm_verify(request.POST)
  return error if error.size > 1
  data = url_escape_hash(request.POST)

  id = params[:id]
  @report = get_report(id)
  return 'No Such Report' if @report.nil?

  if @report.scoring.casecmp('dread').zero?
    data['dread_total'] = data['damage'].to_i + data['reproducability'].to_i + data['exploitability'].to_i + data['affected_users'].to_i + data['discoverability'].to_i
  elsif @report.scoring.casecmp('cvss').zero?
    data = cvss(data, false)
  elsif @report.scoring.casecmp('cvssv3').zero?
    data = cvss(data, true)
  elsif(@report.scoring.downcase == "nist800")
    # call nist800 helper function
    data = nist800(data)
  end

  data['report_id'] = id

  @finding = Findings.new(data)
  @finding.save

  # because of multiple scores we need to make sure all are set
  # => leave it up to the user to make the calculation if they switch mid report

  @finding.dread_total = 0 if @finding.dread_total.nil?
  @finding.nist800_total = 0 if @finding.nist800_total == nil
  @finding.cvss_total = 0 if @finding.cvss_total.nil?
  @finding.risk = 0 if @finding.risk.nil?
  @finding.save

  # for a parameter_pollution on report_id
  redirect to("/report/#{id}/findings")
end

# Edit the finding in a report
get '/report/:id/findings/:finding_id/edit' do
  id = params[:id]

  # Query for the first report matching the report_name
  @report = get_report(id)
  @states = config_options['finding_states']

  return 'No Such Report' if @report.nil?

  finding_id = params[:finding_id]

  # Query for all Findings
  @finding = Findings.first(report_id: id, id: finding_id)

  return 'No Such Finding' if @finding.nil?

  # attachments autocomplete work
  temp_attaches = Attachments.all(report_id: id)
  @attaches = []
  temp_attaches.each do |ta|
    next unless ta.description =~ /\.png$/i || ta.description =~ /\.jpg$/i || ta.description =~ /\.jpeg$/i
    @attaches.push(ta.description)
  end

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)

  haml :findings_edit
end

# Edit a finding in the report
post '/report/:id/findings/:finding_id/edit' do
  # Check for kosher name in report name
  id = params[:id]

  # Query for the report
  @report = get_report(id)
  @states = config_options['finding_states']

  return 'No Such Report' if @report.nil?

  finding_id = params[:finding_id]

  # Query for all Findings
  @finding = Findings.first(report_id: id, id: finding_id)

  return 'No Such Finding' if @finding.nil?

  error = mm_verify(request.POST)
  return error if error.size > 1
  data = url_escape_hash(request.POST)

  data['title'] = data['title']

  if @states
      data['state'] =  @states.find_index(data['state'])
  end

  if @report.scoring.casecmp('dread').zero?
    data['dread_total'] = data['damage'].to_i + data['reproducability'].to_i + data['exploitability'].to_i + data['affected_users'].to_i + data['discoverability'].to_i
  elsif @report.scoring.casecmp('cvss').zero?
    data = cvss(data, false)
  elsif @report.scoring.casecmp('cvssv3').zero?
    data = cvss(data, true)
  elsif(@report.scoring.downcase == "nist800")
    # call nist800 helper function
    data = nist800(data)
  end

  # Update the finding with templated finding stuff
  unless @finding.update(data)
    error = ""
    @finding.errors.each do |f|
      error = error + f.to_s() + "<br>"
    end
    return "<p>The following error(s) were found while trying to update : </p>#{error}"
  end

  # because of multiple scores we need to make sure all are set
  # => leave it up to the user to make the calculation if they switch mid report
  @finding.dread_total = 0 if @finding.dread_total.nil?
  @finding.nist800_total = 0 if @finding.nist800_total == nil
  @finding.cvss_total = 0 if @finding.cvss_total.nil?
  @finding.risk = 0 if @finding.risk.nil?
  @finding.save

  redirect to("/report/#{id}/findings")
end

# Upload a finding from a report into the database
get '/report/:id/findings/:finding_id/upload' do
  # Check for kosher name in report name
  id = params[:id]

  # Query for the report
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  finding_id = params[:finding_id]

  # Query for the finding
  @finding = Findings.first(report_id: id, id: finding_id)

  return 'No Such Finding' if @finding.nil?

  # We can't create a direct copy b/c TemplateFindings doesn't have everything findings does
  # Check model/master.rb to compare
  attr = {
    title: @finding.title,
    damage: @finding.damage,
    reproducability: @finding.reproducability,
    exploitability: @finding.exploitability,
    affected_users: @finding.affected_users,
    discoverability: @finding.discoverability,
    dread_total: @finding.dread_total,
    nist800_total: @finding.nist800_total,
    cvss_base: @finding.cvss_base,
    cvss_impact: @finding.cvss_impact,
    cvss_exploitability: @finding.cvss_exploitability,
    cvss_temporal: @finding.cvss_temporal,
    cvss_environmental: @finding.cvss_environmental,
    cvss_modified_impact: @finding.cvss_modified_impact,
    cvss_total: @finding.cvss_total,
    effort: @finding.effort,
    type: @finding.type,
    overview: @finding.overview,
    poc: @finding.poc,
    remediation: @finding.remediation,
    approved: false,
    references: @finding.references,
    risk: @finding.risk,
    attack_vector: @finding.attack_vector,
    attack_complexity: @finding.attack_complexity,
    privileges_required: @finding.privileges_required,
    user_interaction: @finding.user_interaction,
    scope_cvss: @finding.scope_cvss,
    confidentiality: @finding.confidentiality,
    integrity: @finding.integrity,
    availability: @finding.availability,
    exploit_maturity: @finding.exploit_maturity,
    remeditation_level: @finding.remeditation_level,
    report_confidence: @finding.report_confidence,
    confidentiality_requirement: @finding.confidentiality_requirement,
    integrity_requirement: @finding.integrity_requirement,
    availability_requirement: @finding.availability_requirement,
    mod_attack_vector: @finding.mod_attack_vector,
    mod_attack_complexity: @finding.mod_attack_complexity,
    mod_privileges_required: @finding.mod_privileges_required,
    mod_user_interaction: @finding.mod_user_interaction,
    mod_scope: @finding.mod_scope,
    mod_confidentiality: @finding.mod_confidentiality,
    mod_integrity: @finding.mod_integrity,
    mod_availability: @finding.mod_availability,
    cvss_base_score: @finding.cvss_base_score,
    cvss_impact_score: @finding.cvss_impact_score,
    cvss_mod_impact_score: @finding.cvss_mod_impact_score,
    severity: @finding.severity,
    likelihood: @finding.likelihood
  }

  @new_finding = TemplateFindings.new(attr)
  @new_finding.save

  serpico_log("Finding #{@finding.title} from Report #{id} uploaded to the template database")

  redirect to("/report/#{id}/findings")
end

# Remove a finding from the report
get '/report/:id/findings/remove/:finding_id' do
  # Check for kosher name in report name
  id = params[:id]

  # Query for the report
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  finding_id = params[:finding_id]

  params[:finding_id].split(',').each do |current_id|
    finding = Findings.first(report_id: id, id: current_id)
    return "No Such Finding : #{current_id}" if finding.nil?
    # delete the entries
    finding.destroy
    serpico_log("#{finding.title} deleted from report #{id}")
  end
  redirect to("/report/#{id}/findings")
end

# preview a finding
get '/report/:id/findings/:finding_id/preview' do
  id = params[:id]

  # Query for the report
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  # Query for the Finding
  @finding = Findings.first(report_id: id, id: params[:finding_id])

  return 'No Such Finding' if @finding.nil?

  # this flags edited findings
  if @finding.master_id
    master = TemplateFindings.first(id: @finding.master_id)
    @finding.overview = compare_text(@finding.overview, master.overview)
  end

  ## We have to do some hackery here for wordml
  findings_xml = ''
  findings_xml << '<findings_list>'
  findings_xml << @finding.to_xml
  findings_xml << '</findings_list>'

  findings_xml = meta_markup_unencode(findings_xml, @report)

  report_xml = findings_xml.to_s

  xslt_elem = Xslt.first(finding_template: true)

  if xslt_elem

    # Push the finding from XML to XSLT
    xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

    docx_xml = xslt.transform(Nokogiri::XML(report_xml))

    # We use a temporary file with a random name
    rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

    # Create a temporary copy of the finding_template
    FileUtils.copy_file(xslt_elem.docx_location, rand_file)

    ### IMAGE INSERT CODE
    if docx_xml.to_s =~ /\[!!/
      # first we read in the current [Content_Types.xml]
      content_types = read_rels(rand_file, '[Content_Types].xml')

      # add the png and jpg handling to end of content types document
      if content_types !~ /image\/jpg/
        content_types = content_types.sub('</Types>', '<Default Extension="jpg" ContentType="image/jpg"/></Types>')
      end
      if content_types !~ /image\/png/
        content_types = content_types.sub('</Types>', '<Default Extension="png" ContentType="image/png"/></Types>')
      end
      if content_types !~ /image\/jpeg/
        content_types = content_types.sub('</Types>', '<Default Extension="jpeg" ContentType="image/jpeg"/></Types>')
      end

      docx_modify(rand_file, content_types, '[Content_Types].xml')

      # replace all [!! image !!] in the document
      imgs = docx_xml.to_s.split('[!!')
      docx = imgs.first
      imgs.delete_at(0)

      imgs.each do |image_i|
        name = image_i.split('!!]').first.delete(' ')
        end_xml = image_i.split('!!]').last

        # search for the image in the attachments
        image = Attachments.first(description: name, report_id: id)

        # tries to prevent breakage in the case image dne
        if image
          # inserts the image into the doc
          docx = image_insert(docx, rand_file, image, end_xml)
        else
          docx = docx.sub(/<w:p[^\>]*?>((?<!<w:p[ |>]).)*\z/m, '')
          end_xml = end_xml.sub(/^<\/w:t>.*?<\/w:r>.*?<\/w:p>/m, '')
          docx << end_xml
        end
      end

    else
      # no images in finding
      docx = docx_xml.to_s
    end
    #### END IMAGE INSERT CODE

    docx_modify(rand_file, docx, 'word/document.xml')

    send_file rand_file, type: 'docx', filename: "#{@finding.title}.docx"
  else

    "You don't have a Finding Template (did you delete the default one?) -_- ... If you're an admin go to <a href='/admin/templates/add'>here</a> to add one."

  end
end

# Generate the report
get '/report/:id/generate' do
  id = params[:id]

  # Query for the report
  @report = get_report(id)

  return 'No Such Report' if @report.nil?

  @report.update(scoring: set_scoring(config_options)) unless @report.scoring

  user = User.first(username: get_username)

  if user
    @report.consultant_name = user.consultant_name
    @report.consultant_phone = user.consultant_phone
    @report.consultant_email = user.consultant_email
    @report.consultant_title = user.consultant_title
    @report.consultant_company = user.consultant_company

  else
    @report.consultant_name = ''
    @report.consultant_phone = ''
    @report.consultant_email = ''
    @report.consultant_title = ''
    @report.consultant_company = ''

  end
  @report.save

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800 = get_scoring_findings(@report)

  ## We have to do some hackery here for wordml
  findings_xml = ''
  findings_xml << '<findings_list>'

  finding_number = 1

  @findings.each do |finding|
    finding.finding_number = finding_number
    # This flags new or edited findings
    if finding.master_id
      master = TemplateFindings.first(id: finding.master_id)
      if master
        finding.overview = compare_text(finding.overview, master.overview)
        finding.remediation = compare_text(finding.remediation, master.remediation)
      else
        finding.overview = compare_text(finding.overview, nil)
        finding.remediation = compare_text(finding.remediation, nil)
      end
    else
      finding.overview = compare_text(finding.overview, nil)
      finding.remediation = compare_text(finding.remediation, nil)
    end
    findings_xml << finding.to_xml
    finding_number += 1
  end

  findings_xml << '</findings_list>'

  # Replace the stub elements with real XML elements
  findings_xml = meta_markup_unencode(findings_xml, @report)

  # check if the report has user_defined variables
  if @report.user_defined_variables
    # we need the user defined variables in xml
    udv_hash = JSON.parse(@report.user_defined_variables)
  end

  # adding the udvs to the XML

  # update udv_hash with findings totals
  udv_hash = add_findings_totals(udv_hash, @findings, config_options)

  udv = "<udv>\n"
  udv_hash.each do |key, value|
    udv << "<#{key}>"
    udv << value.to_s
    udv << "</#{key}>\n"
  end
  udv << "</udv>\n"

  # adding the udos to the XML
  udo_xml = "<udo>\n"
  udo_templates = UserDefinedObjectTemplates.all
  udo_templates.each do |udo_template|
    # we only add the udos that are linked to the current report, and linked to its respective template
    udos = UserDefinedObjects.all(report_id: @report.id, template_id: udo_template.id)
    udos.each do |udo|
      udo_xml << "\t<#{udo_template.type.downcase.tr(' ', '_')}>\n"
      properties = JSON.parse(udo.udo_properties)
      properties.each do |prop, value|
        udo_xml << "\t\t<#{prop.downcase.tr(' ', '_')}>"
        udo_xml << value.to_s
        udo_xml << "</#{prop.downcase.tr(' ', '_')}>\n"
      end
      udo_xml << "\t</#{udo_template.type.downcase.tr(' ', '_')}>\n"
    end
  end
  udo_xml << "</udo>\n"
  # if msf connection up, we add services and hosts to the xml
  services_xml = ''
  if (msfsettings = RemoteEndpoints.first(report_id: @report.id))
    if (rpc = msfrpc(@report.id))
      res = rpc.call('console.create')
      rpc.call('db.set_workspace', msfsettings.workspace)
      # We create the XML from the opened services. onlyup undocumented but it does exist
      res = rpc.call('db.services', limit: 10_000, only_up: true)
      msfservices = res['services']
      services_xml_raw = Nokogiri::XML::Builder.new do |xml|
        xml.services do
          msfservices.each do |msfservice|
            xml.service do
              msfservice.each do |key, value|
                xml.send "#{key}_", value
              end
            end
          end
        end
      end
      services_xml = services_xml_raw.doc.root.to_xml
      # we create the XML from the hosts found.
      res = rpc.call('db.hosts', limit: 10_000)
      msfhosts = res['hosts']
      hosts_xml_raw = Nokogiri::XML::Builder.new do |xml|
        xml.hosts do
          msfhosts.each do |msfhost|
            xml.host do
              msfhost.each do |key, value|
                xml.send "#{key}_", value
              end
            end
          end
        end
      end
      hosts_xml = hosts_xml_raw.doc.root.to_xml
    end
  end
  # we add the xml from the attachments the user added
  all_appendices_xml = "<appendices>\n"
  all_appendices = Attachments.all(report_id: id, appendice: true)
  all_appendices.each do |appendice|
    next unless File.file?(appendice.filename_location)
    # the filename without the extension becomes the xml tag
    appendice_xml = "<#{appendice.filename.split('.')[0]}>"
    appendice_xml += Nokogiri::XML(File.open(appendice.filename_location).read).root.to_xml
    appendice_xml += "</#{appendice.filename.split('.')[0]}>"
    all_appendices_xml += appendice_xml.to_s

  end
  all_appendices_xml += "</appendices>\n"

  # We notify all the plugins to get their output and add it to the report xml
  plugins_xml = PluginNotifier.instance.notify_report_generated(@report)

  # we bring all xml together
  report_xml = "<report>#{CGI.unescapeHTML(@report.to_xml)}#{udv}#{findings_xml}#{udo_xml}#{services_xml}#{hosts_xml}#{all_appendices_xml}#{plugins_xml}</report>"
  noko_report_xml = Nokogiri::XML(report_xml)
  #no use to go on with report generation if report XML is malformed
  if !noko_report_xml.errors.empty?
    noko_report_xml.errors.each do |error|
      error = CGI.escapeHTML(error.to_s)
    end
    return "<p>The following error(s) were found in report XML file : </p>#{noko_report_xml.errors.join('<br/>')}<p>This is most often because of malformed metamarkup in findings."
  end

  xslt_elem = Xslt.first(report_type: @report.report_type)

  # Push the finding from XML to XSLT
  xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

  docx_xml = xslt.transform(Nokogiri::XML(report_xml))

  # We use a temporary file with a random name
  rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

  # Create a temporary copy of the word doc
  FileUtils.copy_file(xslt_elem.docx_location, rand_file)

  list_components = {}
  xslt_elem.components.each do |component|
    xslt = Nokogiri::XSLT(File.read(component.xslt_location))
    list_components[component.name] = xslt.transform(Nokogiri::XML(report_xml))
  end
  ### IMAGE INSERT CODE
  if docx_xml.to_s =~ /\[!!/
    # first we read in the current [Content_Types.xml]
    content_types = read_rels(rand_file, '[Content_Types].xml')

    # add the png and jpg handling to end of content types document
    if content_types !~ /image\/jpg/
      content_types = content_types.sub('</Types>', '<Default Extension="jpg" ContentType="image/jpg"/></Types>')
    end
    if content_types !~ /image\/png/
      content_types = content_types.sub('</Types>', '<Default Extension="png" ContentType="image/png"/></Types>')
    end
    if content_types !~ /image\/jpeg/
      content_types = content_types.sub('</Types>', '<Default Extension="jpeg" ContentType="image/jpeg"/></Types>')
    end

    docx_modify(rand_file, content_types, '[Content_Types].xml')

    # replace all [!! image !!] in the document
    imgs = docx_xml.to_s.split('[!!')
    docx = imgs.first
    imgs.delete_at(0)

    imgs.each do |image_i|
      name = image_i.split('!!]').first.delete(' ')
      end_xml = image_i.split('!!]').last

      # search for the image in the attachments
      image = Attachments.first(description: name, report_id: id)

      # tries to prevent breakage in the case image dne
      if image
        # inserts the image
        docx = image_insert(docx, rand_file, image, end_xml)
      else
        docx << end_xml
      end
    end
  else
    # no images in finding
    docx = docx_xml.to_s
  end
  #### END IMAGE INSERT CODE

  # Get hyperlinks and References
  hyperlinks = updateHyperlinks(docx)
  # Update _rels directrory
  rels_file =  read_rels(rand_file, 'word/_rels/document.xml.rels')
  # Noko syntax rels
  noko_rels =  Nokogiri::XML(rels_file)
  urls = hyperlinks['urls']
  id = hyperlinks['id']
  for i in 0..id.length - 1
    url =  urls[i]
    cid =  id[i]
    noko_rels.root.first_element_child.after("<Relationship Id=\"#{cid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"#{url.delete(' ')}\" TargetMode=\"External\"/>")
  end

  content_to_write = noko_rels.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML).strip
  # Edit Relationships file
  write_rels(rand_file, 'word/_rels/document.xml.rels', content_to_write)
  # Update hyperlinks
  docx = hyperlinks['xmlText']

  docx_modify(rand_file, docx, 'word/document.xml')

  list_components.each do |name, xml|
    docx_modify(rand_file, xml.to_s, name)
  end

  serpico_log("Report generation attempted, Report Name: #{@report.report_name} #{rand_file} #{xslt_elem.xslt_location}")
  send_file rand_file, type: 'docx', filename: "#{@report.report_name}.docx"
end

# Export a report
get '/report/:id/export' do
  json = {}

  id = params[:id]
  report = get_report(id)

  # bail without a report
  redirect to('/') unless report

  # add the report
  json['report'] = report

  # add the findings
  findings = Findings.all(report_id: id)
  json['findings'] = findings

  # add the exports
  attachments = Attachments.all(report_id: id)
  json['Attachments'] = attachments

  local_filename = "./tmp/#{rand(36**12).to_s(36)}.json"
  File.open(local_filename, 'w') { |f| f.write(JSON.pretty_generate(json)) }

  send_file local_filename, type: 'json', filename: 'exported_report.json'
end

# Import a report
get '/report/import' do
  haml :import_report
end

# Import a report
post '/report/import' do
  redirect to('/report/import') unless params[:file]

  # reject if the file is above a certain limit
  if params[:file][:tempfile].size > 100_000_000
    return 'File too large. 100MB limit'
  end

  json_file = params[:file][:tempfile].read
  line = JSON.parse(json_file)

  line['report']['id'] = nil

  f = Reports.create(line['report'])
  f.save

  # now add the findings
  line['findings'].each do |finding|
    finding['id'] = nil
    finding['master_id'] = nil
    finding['report_id'] = f.id
    finding['finding_modified'] = nil

    finding['dread_total'] = 0 if finding['dread_total'].nil?
    finding['cvss_total'] = 0 if finding['cvss_total'].nil?
    finding['risk'] = 1 if finding['risk'].nil?

    g = Findings.create(finding)
    g.save
  end

  if line['Attachments']
    # now add the attachments
    line['Attachments'].each do |attach|
      serpico_log("Importing attachments to #{f.id}")
      attach['id'] = nil

      attach['filename'] = 'Unknown' if attach['filename'].nil?
      if attach['filename_location'] =~ /./
        a = attach['filename_location'].split('.').last
        loc = './attachments/' + a.gsub('/attachments/', '')
        attach['filename_location'] = loc
      else
        loc = './attachments/' + attach['filename_location']
      end
      attach['filename_location'] = loc

      attach['report_id'] = f.id
      attach['description'] = 'No description' if attach['description'].nil?
      g = Attachments.create(attach)
      g.save
    end
  end

  # we should redirect to the newly imported report
  redirect to("/report/#{f.id}/edit")
end
get '/report/:id/text_status' do
  id = params[:id]
  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  # add the findings
  @findings = Findings.all(report_id: id)

  haml :text_status
end

# generate an asciidoc version of current findings
get '/report/:id/asciidoc_status' do
  id = params[:id]
  report = get_report(id)

  # bail without a report
  redirect to('/') unless report

  # add the findings
  findings = Findings.all(report_id: id)

  ascii_doc_ = ''
  findings.each do |finding|
    ascii_doc_ << gen_asciidoc(finding, report.scoring)
  end

  local_filename = "./tmp/#{rand(36**12).to_s(36)}.asd"
  File.open(local_filename, 'w') { |f| f.write(ascii_doc_) }

  send_file local_filename, type: 'txt', filename: "report_#{id}_findings.asd"
end

# generate a csv with the current report findings
get '/report/:id/csv_export' do
  id = params[:id]
  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  # add the findings
  @findings = Findings.all(report_id: id)
  csv_doc_ = "Finding Title|Risk Rating|Remediation Effort|Type|Overview|Remediation\n"
  @findings.each do |finding|
    csv_doc_ << "#{finding.title}|#{finding.risk}|#{finding.effort}|#{finding.type}|#{finding.overview}|#{finding.remediation}\n"
  end
  # change some text around so the findings actually make sense and don't have a ton of garbage in them
  csv_doc_ = csv_doc_.gsub(/<paragraph>/, '')
  csv_doc_ = csv_doc_.gsub(/<\/paragraph>/, '')
  csv_doc_ = csv_doc_.gsub(/\|0\|/, '|Informational|')
  csv_doc_ = csv_doc_.gsub(/\|1\|/, '|Low|')
  csv_doc_ = csv_doc_.gsub(/\|2\|/, '|Moderate|')
  csv_doc_ = csv_doc_.gsub(/\|3\|/, '|High|')
  csv_doc_ = csv_doc_.gsub(/\|4\|/, '|Critical|')
  local_filename = "./tmp/#{rand(36**12).to_s(36)}.csv"
  File.open(local_filename, 'w') { |f| f.write(csv_doc_) }
  send_file local_filename, type: 'txt', filename: "report_#{id}_findings.csv"
end

# generate a presentation of current report
get '/report/:id/presentation' do
  # check the user has installed reveal
  unless File.directory?(Dir.pwd + '/public/reveal.js')
    return "reveal.js not found in /public/ directory. To install:<br><br> 1. Goto [INSTALL_DIR]/public/ <br>2.run 'git clone https://github.com/hakimel/reveal.js.git'<br>3. Restart Serpico"
  end

  id = params[:id]

  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix,@nist800  = get_scoring_findings(@report)

  # add images into presentations
  @images = []
  @findings.each do |find|
    next unless find.presentation_points
    find.presentation_points.to_s.split('<paragraph>').each do |pp|
      a = {}
      next unless pp =~ /\[\!\!/
      img = pp.split('[!!')[1].split('!!]').first
      a['name'] = img
      if Attachments.first(description: img)
        img_p = Attachments.first(description: img)
      else
        return "attachment #{img} from vulnerability <a href=/report/#{find.report_id}/findings/#{find.id}/edit#pocu> #{find.title}</a> doesn't exist. Did you mistype something?"
      end
      a['link'] = "/report/#{id}/attachments/" + img_p.id.to_s
      @images.push(a)
    end
  end

  haml :presentation, layout: false
end

# export presentation of current report in html format, inside a zip
get '/report/:id/presentation_export' do
  # check the user has installed reveal
  unless File.directory?(Dir.pwd + '/public/reveal.js')
    return "reveal.js not found in /public/ directory. To install:<br><br> 1. Goto [INSTALL_DIR]/public/ <br>2.run 'git clone https://github.com/hakimel/reveal.js.git'<br>3. Restart Serpico"
    sleep(30)
    redirect to('/')
  end

  id = params[:id]

  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix = get_scoring_findings(@report)

  # add images into presentations
  @images = []
  @findings.each do |find|
    next unless find.presentation_points
    find.presentation_points.to_s.split('<paragraph>').each do |pp|
      a = {}
      next unless pp =~ /\[\!\!/
      img = pp.split('[!!')[1].split('!!]').first
      a['name'] = img
      if Attachments.first(description: img)
        img_p = Attachments.first(description: img)
      else
        return "attachment #{img} from vulnerability <a href=/report/#{find.report_id}/findings/#{find.id}/edit#pocu> #{find.title}</a> doesn't exist. Did you mistype something?"
      end
      a['link'] = "/report/#{id}/attachments/#{img_p.id}"
      @images.push(a)
    end
  end

  # create html file from haml template
  template = File.read(Dir.pwd + '/views/presentation.haml')
  haml_engine = Haml::Engine.new(template)
  output = haml_engine.render(Object.new, :@report => @report, :@findings => @findings, :@dread => @dread, :@cvss => @cvss, :@cvss3 => @cvss3, :@riskmatrix => @riskmatrix, :@images => @images)
  rand_file = Dir.pwd + "/tmp/#{rand(36**12).to_s(36)}.html"
  newHTML = Nokogiri::HTML(output)

  # Each link inside the HTML file is considered as a dependency that will need to be fixed to a relative local path
  dependencies = []

  # fix href and src based links in the html to relative local URL. This should cover most of the use cases.
  newHTML.css('[href]').each do |el|
    if el.attribute('href').to_s[1, 6] != 'report' && !(dependencies.include? el.attribute('href').to_s[1..-1])
      dependencies.push(el.attribute('href').to_s[1..-1])
    end
    el.set_attribute('href', '.' + el.attribute('href'))
  end

  newHTML.css('[src]').each do |el|
    if el.attribute('src').to_s[1, 6] != 'report' && !(dependencies.include? el.attribute('src').to_s[1..-1])
      dependencies.push(el.attribute('src').to_s[1..-1])
    end
    el.set_attribute('src', '.' + el.attribute('src'))
  end

  # *slightly ugly* way to fix links in the HTML that aren't in a href or src (for exemple in javascript)
  htmlDoc = newHTML.to_html
  # the regex match stuff like '/img/reveal.js/foo/lib.js', "/css/reveal.js/theme/special.css"
  link = htmlDoc[/(\'|\")(\/(img|js|css|reveal\.js|fonts)\/(\S*\/)*\S*\.\S*)(\'|\")/, 2]
  until link.nil?
    dependencies.push(link[1..-1]) unless dependencies.include? link[1..-1]
    htmlDoc[/(\'|\")(\/(img|js|css|reveal\.js|fonts)\/(\S*\/)*\S*\.\S*)(\'|\")/, 2] = ".#{link}"
    link = htmlDoc[/(\'|\")(\/(img|js|css|reveal\.js|fonts)\/(\S*\/)*\S*\.\S*)(\'|\")/, 2]
  end

  # save html with links fixed to a relative local path
  File.open(rand_file, 'w') do |f|
    f.write htmlDoc
  end

  @findings,@dread,@cvss,@cvssv3,@risk,@riskmatrix,@nist800 = get_scoring_findings(@report)
  rand_zip = Dir.pwd + "/tmp/#{rand(36**12).to_s(36)}.zip"

  # put the presentation and its dependencies (links, images, libraries...) in a zip file
  Zip.setup do |c|
    c.on_exists_proc = true
    c.continue_on_exists_proc = true
  end
  Zip::File.open(rand_zip, Zip::File::CREATE) do |zipfile|
    zipfile.add('presentation.html', rand_file)

    # put the public directory in the zip file.
    list_public_file = Dir.glob(Dir.pwd + '/public/**/*')
    list_public_file.each do |file|
      # don't add directory or .git files in the zip
      if file['.git'].nil? && File.file?(file)
        # if file is .js or .css, check if it has dependencies that needs to be fixed to relative local path
        if !file[/\.(js|css)$/].nil?
          file_content = File.read(file)
          until link.nil?
            file_content[/(\'|\")(\/(img|js|css|reveal\.js|fonts)\/(\S*\/)*\S*\.\S*)(\'|\")/, 2] = ".#{link}"
            link = file_content[/(\'|\")(\/(img|js|css|reveal\.js|fonts)\/(\S*\/)*\S*\.\S*)(\'|\")/, 2]
          end
          rand_temp_file = Dir.pwd + "/tmp/#{rand(36**12).to_s(36)}.tmp"
          File.open(rand_temp_file, 'w') do |f|
            f.write file_content
          end
          # remove Serpico/public from the file path and put it in the zip
          zipfile.add(file[(Dir.pwd + '/public/').length..-1], rand_temp_file)
        else
          # remove Serpico/public from the file path and put it in the zip
          zipfile.add(file[(Dir.pwd + '/public/').length..-1], file)
        end
      end
    end
    # put attachements in the zip
    @images.each do |images|
      img_p = Attachments.first(description: images['name'])
      zipfile.add("report/#{id}/attachments/#{img_p.id}", img_p.filename_location)
    end
  end

  send_file rand_zip, type: 'zip', filename: "#{@report.report_name}.zip"
end

# set msf rpc settings for report
get '/report/:id/msfsettings' do
  id = params[:id]
  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  @vulnmap = config_options['vulnmap']
  @msfsettings = RemoteEndpoints.first(report_id: id)

  haml :msfsettings
end

# set msf rpc settings for report
post '/report/:id/msfsettings' do
  id = params[:id]
  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  return 'Metasploit integration not enabled' unless config_options['vulnmap']

  msfsettings = RemoteEndpoints.first(report_id: id)

  if msfsettings
    msfsettings.update(ip: params[:ip], port: params[:port], workspace: params[:workspace], user: params[:user], pass: params[:pass])
  else
    msfsettings = RemoteEndpoints.new
    msfsettings['report_id'] = @report.id
    msfsettings['ip'] = params[:ip]
    msfsettings['port'] = params[:port]
    msfsettings['type'] = 'msfrpc'
    msfsettings['workspace'] = params[:workspace]
    msfsettings['user'] = params[:user]
    msfsettings['pass'] = params[:pass]
    msfsettings.save
  end

  redirect to("/report/#{@report.id}/findings")
end

# display hosts from msf db
get '/report/:id/hosts' do
  id = params[:id]
  @report = get_report(id)
  @vulnmap = config_options['vulnmap']

  # bail without a report
  redirect to('/') unless @report

  msfsettings = RemoteEndpoints.first(report_id: id)
  unless msfsettings
    return "You need to setup a metasploit RPC connection to use this feature. Do so <a href='/report/#{id}/msfsettings'>here</a>"
  end

  # setup msfrpc handler
  rpc = msfrpc(@report.id)
  if rpc == false
    return 'ERROR: Connection to metasploit failed. Make sure you have msfprcd running and the settings in Serpico are correct.'
  end

  # get hosts from msf db
  res = rpc.call('console.create')
  rpc.call('db.set_workspace', msfsettings.workspace)
  res = rpc.call('db.hosts', limit: 10_000)
  @hosts = res['hosts']

  haml :dbhosts
end

# display services from msf db
get '/report/:id/services' do
  id = params[:id]
  @report = get_report(id)
  @vulnmap = config_options['vulnmap']

  # bail without a report
  redirect to('/') unless @report

  msfsettings = RemoteEndpoints.first(report_id: id)
  unless msfsettings
    return "You need to setup a metasploit RPC connection to use this feature. Do so <a href='/report/#{id}/msfsettings'>here</a>"
  end

  # setup msfrpc handler
  rpc = msfrpc(@report.id)
  if rpc == false
    return 'ERROR: Connection to metasploit failed. Make sure you have msfprcd running and the settings in Serpico are correct.'
  end

  # get hosts from msf db
  res = rpc.call('console.create')
  rpc.call('db.set_workspace', msfsettings.workspace)
  # onlyup undocumented but it does exist
  res = rpc.call('db.services', limit: 10_000, only_up: true)
  @services = res['services']

  haml :dbservices
end

# display vulns from msf db
get '/report/:id/vulns' do
  id = params[:id]
  @report = get_report(id)
  @vulnmap = config_options['vulnmap']

  # bail without a report
  redirect to('/') unless @report

  msfsettings = RemoteEndpoints.first(report_id: id)
  unless msfsettings
    return "You need to setup a metasploit RPC connection to use this feature. Do so <a href='/report/#{id}/msfsettings'>here</a>"
  end

  # setup msfrpc handler
  rpc = msfrpc(@report.id)
  if rpc == false
    return 'connection to MSF RPC deamon failed. Make sure you have msfprcd running and the settings in Serpico are correct.'
  end

  # get vulns from msf db
  res = rpc.call('console.create')
  rpc.call('db.set_workspace', msfsettings.workspace)
  res = rpc.call('db.vulns', limit: 10_000)
  @vulns = res['vulns']

  haml :dbvulns
end

# autoadd vulns from msf db
get '/report/:id/import/vulns' do
  id = params[:id]
  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  return 'No Such Report' if @report.nil?

  return 'Metasploit integration not enabled.' unless config_options['vulnmap']

  add_findings = []
  dup_findings = []
  autoadd_hosts = {}

  # load msf settings
  msfsettings = RemoteEndpoints.first(report_id: id)
  unless msfsettings
    return "You need to setup a metasploit RPC connection to use this feature. Do so <a href='/report/#{id}/msfsettings'>here</a>"
  end

  # setup msfrpc handler
  rpc = msfrpc(@report.id)
  if rpc == false
    return 'connection to MSF RPC deamon failed. Make sure you have msfprcd running and the settings in Serpico are correct.'
  end

  # determine findings to add from vuln data
  vulns = get_vulns_from_msf(rpc, msfsettings.workspace)

  # load all findings
  @findings = TemplateFindings.all(order: [:title.asc])

  # determine findings to add from vuln data
  # host/ip is key, value is array of vuln ids
  vulns.keys.each do |i|
    vulns[i].each do |v|
      # if serpico finding id maps to a ref from MSF vuln db, add to report
      @mappings = VulnMappings.all(msf_ref: v)
      # add affected hosts for each finding
      next unless @mappings
      @mappings.each do |m|
        if autoadd_hosts[m.templatefindings_id]
          # only one host/url per finding (regardless of ports and urls). this should change in the future
          unless autoadd_hosts[m.templatefindings_id].include?(i)
            autoadd_hosts[m.templatefindings_id] << i
          end
        else
          autoadd_hosts[m.templatefindings_id] = []
          autoadd_hosts[m.templatefindings_id] << i
        end
        add_findings << m.templatefindings_id
      end
    end
  end

  add_findings = add_findings.uniq

  # create new findings from an import
  # TODO: This will duplicate if the user already has a nessus id mapped
  if config_options['auto_import']
    p 'auto_import function not supported with MSF intergration'
  end

  if add_findings.empty?
    redirect to("/report/#{id}/findings")
  else
    @autoadd = true

    add_findings.each do |finding|
      # if the finding already exists in the report dont add
      currentfindings = Findings.all(report_id: id)
      currentfindings.each do |cf|
        next unless cf.master_id == finding.to_i
        dup_findings << finding.to_i unless dup_findings.include?(finding.to_i)
        add_findings.delete(finding.to_i)
      end
    end
    @autoadd_hosts = autoadd_hosts
    @dup_findings = dup_findings.uniq
    @autoadd_findings = add_findings
  end
  haml :findings_add
end

# get enabled plugins
get '/report/:id/report_plugins' do
  id = params[:id]
  @report = get_report(id)

  # bail without a report
  redirect to('/') unless @report

  @menu = []
  Dir[File.join(File.dirname(__FILE__), '../plugins/**/', '*.json')].each do |lib|
    pl = JSON.parse(File.open(lib).read)
    a = {}
    next unless pl['enabled'] && pl['report_view']
    # add the plugin to the menu
    a['name'] = pl['name']
    a['description'] = pl['description']
    a['link'] = pl['link']
    @menu.push(a)
  end
  haml :enabled_plugins
end

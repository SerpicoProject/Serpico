require 'zip'
require 'sinatra'

######
# Template Document Routes
######

config_options = JSON.parse(File.read('./config.json'))

# These are the master routes, they control the findings database
# List Available Templated Findings
get '/master/findings' do
    @findings = TemplateFindings.all(:order => [:title.asc])
    @master = true
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]

    haml :findings_list, :encode_html => true
end

# Create a new templated finding
get '/master/findings/new' do
    @master = true
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]
    @nessusmap = config_options["nessusmap"]
    @vulnmap = config_options["vulnmap"]

    haml :create_finding, :encode_html => true
end

# Create the finding in the DB
post '/master/findings/new' do
    data = url_escape_hash(request.POST)

    if(config_options["dread"])
        data["dread_total"] = data["damage"].to_i + data["reproducability"].to_i + data["exploitability"].to_i + data["affected_users"].to_i + data["discoverability"].to_i
    end

    # split out any nessus mapping data
    nessusdata = Hash.new()
    nessusdata["pluginid"] = data["pluginid"]
    data.delete("pluginid")

    # split out any vuln mapping data
    vulnmapdata = Hash.new()
    vulnmapdata["msf_ref"] = data["msf_ref"]
    data.delete("msf_ref")

    @finding = TemplateFindings.new(data)
    @finding.save

    # find the id of the newly created finding so we can link mappings to it
    @newfinding = TemplateFindings.first(:title => data["title"], :order => [:id.desc], :limit => 1)

    # save mapping data
    if (config_options["nessusmap"] && nessusdata["pluginid"])
        nessusdata["templatefindings_id"] = @finding.id
        @nessus = NessusMapping.new(nessusdata)
        @nessus.save
    end
    if (config_options["vulnmap"] && vulnmapdata["msf_ref"])
        vulnmapdata["templatefindings_id"] = @finding.id
        @vulnmappings = VulnMappings.new(vulnmapdata)
        @vulnmappings.save
    end

    if (config_options["cvss"])
        data = cvss(data)
    end

    redirect to('/master/findings')
end

# Edit the templated finding
get '/master/findings/:id/edit' do
    @master = true
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]
    @nessusmap = config_options["nessusmap"]
    @burpmap = config_options["burpmap"]
    @vulnmap = config_options["vulnmap"]

    # Check for kosher name in report name
    id = params[:id]

    # Query for Finding
    @finding = TemplateFindings.first(:id => id)
	  @templates = Xslt.all()

    if (@nessusmap)
        @nessus = NessusMapping.all(:templatefindings_id => id)
    end

    if (@burpmap)
        @burp = BurpMapping.all(:templatefindings_id => id)
    end

    if (@vulnmap)
        @vulnmaps = VulnMappings.all(:templatefindings_id => id)
    end

    if @finding == nil
        return "No Such Finding"
    end

    haml :findings_edit, :encode_html => true
end

# Edit a finding
post '/master/findings/:id/edit' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)

    if @finding == nil
        return "No Such Finding"
    end

    data = url_escape_hash(request.POST)

    if data["approved"] == "on"
        data["approved"] = true
    else
        data["approved"] = false
    end

    # to prevent title's from degenerating with &gt;, etc. [issue 237]
    data["title"] = data["title"].gsub('&amp;','&')

    if(config_options["dread"])
        data["dread_total"] = data["damage"].to_i + data["reproducability"].to_i + data["exploitability"].to_i + data["affected_users"].to_i + data["discoverability"].to_i
    elsif(config_options["cvss"])
        data = cvss(data)
    end

    # split out any nessus mapping data
    nessusdata = Hash.new()
    nessusdata["pluginid"] = data["nessus_pluginid"]
    data.delete("nessus_pluginid")
    nessusdata["templatefindings_id"] = id

    # split out any burp mapping data
    burpdata = Hash.new()
    burpdata["pluginid"] = data["burp_pluginid"]
    data.delete("burp_pluginid")
    burpdata["templatefindings_id"] = id

    # split out any vuln mapping data
    vulnmappingdata = Hash.new()
    vulnmappingdata["msf_ref"] = data["msf_ref"]
    data.delete("msf_ref")
    vulnmappingdata["templatefindings_id"] = id

    # Update the finding with templated finding stuff
    @finding.update(data)

    # save nessus mapping data to db
    if(config_options["nessusmap"])
        @nessus = NessusMapping.new(nessusdata)
        @nessus.save
    end

    # save burp mapping data to db
    if(config_options["burpmap"])
        @burp = BurpMapping.new(burpdata)
        @burp.save
    end

    # save vuln mapping data to db
    if(config_options["vulnmap"])
        @vulnmappings = VulnMappings.new(vulnmappingdata)
        @vulnmappings.save
    end

    redirect to("/master/findings")
end

# Delete a template finding
get '/master/findings/:id/delete' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)

    if @finding == nil
        return "No Such Finding"
    end

    # delete associated vuln mappings
    @vulnmappings = VulnMappings.all(:templatefindings_id => id)
    @vulnmappings.destroy

    # Update the finding with templated finding stuff
    @finding.destroy

    redirect to("/master/findings")
end

# preview a finding
get '/master/findings/:id/preview' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)

    if @finding == nil
        return "No Such Finding"
    end

    ## We have to do some hackery here for wordml
    findings_xml = ""
    findings_xml << "<findings_list>"
    findings_xml << @finding.to_xml
    findings_xml << "</findings_list>"

    findings_xml = meta_markup_unencode(findings_xml, nil)

    # this is the master db so we have to do a bait and switch
    # The other option is creating a master finding specific docx
    findings_xml = findings_xml.gsub("<template_findings>","<findings>")
    findings_xml = findings_xml.gsub("</template_findings>;","</template_findings>")

    report_xml = "#{findings_xml}"

    xslt_elem = Xslt.first(:finding_template => true)

    if xslt_elem

        # Push the finding from XML to XSLT
        xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

        docx_xml = xslt.transform(Nokogiri::XML(report_xml))

        # We use a temporary file with a random name
        rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

        # Create a temporary copy of the finding_template
        FileUtils::copy_file(xslt_elem.docx_location,rand_file)

        # modify docx
        docx_modify(rand_file,docx_xml,'word/document.xml')

        send_file rand_file, :type => 'docx', :filename => "#{@finding.title}.docx"

    else
        "You don't have a Finding Template (did you delete the temp?) -_- ... If you're an admin go to <a href='/admin/templates/add'>here</a> to add one.'"
    end
end

# Export a findings database
get '/master/export' do
    json = ""

    findings = TemplateFindings.all

    local_filename = "./tmp/#{rand(36**12).to_s(36)}.json"
    File.open(local_filename, 'w') {|f| f.write(JSON.pretty_generate(findings)) }

    send_file local_filename, :type => 'json', :filename => "template_findings.json"
end

# Import a findings database
get '/master/import' do
    haml :import_templates
end

# Import a findings database
post '/master/import' do
    redirect to("/master/import") unless params[:file]

    # reject if the file is above a certain limit
    if params[:file][:tempfile].size > 1000000
        return "File too large. 1MB limit"
    end

    json_file = params[:file][:tempfile].read
    line = JSON.parse(json_file)

    line.each do |j|
        j["id"] = nil

        finding = TemplateFindings.first(:title => j["title"])

        if finding
            #the finding title already exists in the database
            if finding["overview"] == j["overview"] and finding["remediation"] == j["remediation"]
                # the finding already exists, ignore it
            else
                # it's a modified finding
                j["title"] = "#{j['title']} - [Uploaded Modified Templated Finding]"
                params[:approved] !=nil ? j["approved"] = true : j["approved"] = false
                f = TemplateFindings.create(j)
                f.save
            end
        else
            params[:approved] != nil ? j["approved"] = true : j["approved"] = false
            f = TemplateFindings.first_or_create(j)
            f.save
        end
    end
    redirect to("/master/findings")
end


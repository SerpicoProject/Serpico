require 'rubygems'
require 'zip'

def docx_modify(rand_file,docx_xml,fil_r)
	Zip::File.open(rand_file) do |zipfile|
	  zipfile.get_output_stream(fil_r) {|f| f.write(docx_xml)}
	end
end

def read_rels(zipfile,fil_r)
	content_types = ""

	Zip::File.open(zipfile) do |zipfile|
	  content_types = zipfile.read(fil_r)
	end

	return content_types
end

def zip_attachments(zip_file)
  Zip::Archive.open(zip_file, Zip::CREATE) do |zipfile|
    Dir["../attachments/*" ].each do | name|
      zipfile.add_file(name)
    end
  end
end

# this tallies the findings by criticality and sets them as a udv
def add_findings_totals(udv, findings, config_options)
	critical = 0
	high = 0
	moderate = 0
	low = 0
	informational = 0

	unless udv
		udv = {}
	end

    # Query for the findings that match the report_id
    if(config_options["dread"])
    	findings.each do |finding|
    		if finding.dread_total >= 40
    			critical += 1
    		elsif finding.dread_total >= 30 and finding.dread_total < 40
    			high += 1
    		elsif finding.dread_total >= 20 and finding.dread_total <= 30
    			moderate += 1
    		elsif finding.dread_total >= 10 and finding.dread_total <= 20
    			low += 1
    		elsif finding.dread_total >= 0 and finding.dread_total <= 10
    			informational += 1
    		end
	    end
    elsif(config_options["cvss"])
    	findings.each do |finding|
    		if finding.cvss_total >= 7
    			high += 1
    		elsif finding.cvss_total >= 4 and finding.cvss_total <= 6.9
    			moderate += 1
    		elsif finding.cvss_total >= 0 and finding.cvss_total <= 3.9
    			low += 1
    		end
	    end
    elsif(config_options["cvssv3"])
    	findings.each do |finding|
    		if finding.cvss_total >= 9
    			critical += 1
    		elsif finding.cvss_total >= 7 and finding.cvss_total <= 8.9
    			high += 1
    		elsif finding.cvss_total >= 4 and finding.cvss_total <= 6.9
    			moderate += 1
    		elsif finding.cvss_total >= 0 and finding.cvss_total <= 3.9
    			low += 1
    		end
	    end
    else
    	findings.each do |finding|
    		if finding.risk == 4
    			critical += 1
    		elsif finding.risk == 3
    			high += 1
    		elsif finding.risk == 2
    			moderate += 1
    		elsif finding.risk == 1
    			low += 1
    		elsif finding.risk == 0
    			informational += 1
    		end
	    end
    end

    udv["critical_tally"] = critical
    udv["high_tally"] = high
    udv["moderate_tally"] = moderate
    udv["low_tally"] = low
    udv["informational_tally"] = informational

    return udv
end


# The helper class exists to do string manipulation and heavy lifting
def url_escape_hash(hash)
	hash.each do |k,v|
		v = CGI::escapeHTML(v)

    if v
			# convert bullets
			v = v.gsub("*-","<bullet>")
			v = v.gsub("-*","</bullet>")

			#convert h4
			v = v.gsub("[==","<h4>")
			v = v.gsub("==]","</h4>")

      		#convert indent text
			v = v.gsub("[--","<indented>")
			v = v.gsub("--]","</indented>")

			#convert indent text
			v = v.gsub("[~~","<italics>")
			v = v.gsub("~~]","</italics>")
    end

		# replace linebreaks with paragraph xml elements
		if v =~ /\r\n/
			new_v = ""
			brs = v.split("\r\n")
			brs.each do |br|
				new_v << "<paragraph>"
				new_v << br
				new_v << "</paragraph>"
			end

			v = new_v
		elsif k == "remediation" or k == "overview" or k == "poc" or k == "affected_hosts" or k == "references"
			new_v = "<paragraph>#{v}</paragraph>"
			v = new_v
		end

		hash[k] = v
	end

	return hash
end

def meta_markup(text)
	new_text = text.gsub("<paragraph>","&#x000A;").gsub("</paragraph>","")
	new_text = new_text.gsub("<bullet>","*-").gsub("</bullet>","-*")
	new_text = new_text.gsub("<h4>","[==").gsub("</h4>","==]")
	new_text = new_text.gsub("<code>","[[[").gsub("</code>","]]]")
	new_text = new_text.gsub("<indented>","[--").gsub("</indented>","--]")
	new_text = new_text.gsub("<italics>","[~~").gsub("</italics>","~~]")
end


# URL escaping messes up the inserted XML, this method switches it back to XML elements

def meta_markup_unencode(findings_xml, report)

  # code tags get added in later
	findings_xml = findings_xml.gsub("[[[","<code>")
	findings_xml = findings_xml.gsub("]]]","</code>")

	# creates paragraphs
	findings_xml = findings_xml.gsub("&lt;paragraph&gt;","<paragraph>")
	findings_xml = findings_xml.gsub("&lt;/paragraph&gt;","</paragraph>")
	# same for the bullets
	findings_xml = findings_xml.gsub("&lt;bullet&gt;","<bullet>")
	findings_xml = findings_xml.gsub("&lt;/bullet&gt;","</bullet>")
	# same for the h4
	findings_xml = findings_xml.gsub("&lt;h4&gt;","<h4>")
	findings_xml = findings_xml.gsub("&lt;/h4&gt;","</h4>")
	# same for the code markings
	findings_xml = findings_xml.gsub("&lt;code&gt;","<code>")
	findings_xml = findings_xml.gsub("&lt;/code&gt;","</code>")
	# same for the indented text
	findings_xml = findings_xml.gsub("&lt;indented&gt;","<indented>")
	findings_xml = findings_xml.gsub("&lt;/indented&gt;","</indented>")
	# same for the indented text
	findings_xml = findings_xml.gsub("&lt;italics&gt;","<italics>")
	findings_xml = findings_xml.gsub("&lt;/italics&gt;","</italics>")

  # changes the <<any_var>> marks
    for i in report.instance_variables
        report_property = i[1..-1]
        findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;#{report_property}&amp;gt;&amp;gt;","#{report.instance_variable_get("@#{report_property}")}")
    end

    if report and report.user_defined_variables
        udv_hash = JSON.parse(report.user_defined_variables)
        udv_hash.each do |key,value|
        	findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;#{key}&amp;gt;&amp;gt;","#{value}")
        end
    end

  #this is for re-upping the comment fields
  findings_xml = findings_xml.gsub("&lt;modified&gt;","<modified>")
  findings_xml = findings_xml.gsub("&lt;/modified&gt;","</modified>")

  findings_xml = findings_xml.gsub("&lt;new_finding&gt;","<new_finding>")
  findings_xml = findings_xml.gsub("&lt;/new_finding&gt;","</new_finding>")

  # these are for beautification
  findings_xml = findings_xml.gsub("&amp;quot;","\"")
  findings_xml = findings_xml.gsub("&amp;","&")
  findings_xml = findings_xml.gsub("&amp;lt;","&lt;").gsub("&amp;gt;","&gt;")

  return findings_xml
end

# verify that the markup is sane
def mm_verify(hash)
	error = ""

	hash.each do |k,text|
		text = CGI::escapeHTML(text)

    	if text

			if text.include?("*-")
				elem = text.split("*-")
				elem.shift
				elem.each do |bl|
					if !text.include?("-*")
						error = "Markdown error, missing -* close tag."
					end
				end
			end

			if text.include?("[==")
				elem = text.split("[==")
				elem.shift
				elem.each do |bl|
					if !text.include?("==]")
						error = "Markdown error, missing ==] close tag."
					end
				end
			end

			if text.include?("[~~")
				elem = text.split("[~~")
				elem.shift
				elem.each do |bl|
					if !text.include?("~~]")
						error = "Markdown error, missing ~~] close tag."
					end
				end
			end

			if text.include?("[[[")
				elem = text.split("[[[")
				elem.shift
				elem.each do |bl|
					if !text.include?("]]]")
						error = "Markdown error, missing ]]] close tag."
					end
				end
			end
		end
	end
	return error
end

def compare_text(new_text, orig_text)
 if orig_text == nil
    # there is no master finding, must be new
    t = ""
    t << "<new_finding></new_finding>#{new_text}"
    return t
  end

  if new_text == orig_text
    return new_text
  else
    n_t = ""

    n_t << "<modified></modified>#{new_text}"
    return n_t
  end
end

# CVSS helper, there is a lot of hardcoded stuff
def cvss(data, is_cvssv3)

	# todo this needs to be refactored, cvss2 is calculated everytime

	if not is_cvssv3
		av = data["av"].downcase
		ac = data["ac"].downcase
		au = data["au"].downcase
		c = data["c"].downcase
		i = data["i"].downcase
		a = data["a"].downcase
		e = data["e"].downcase
		rl = data["rl"].downcase
		rc = data["rc"].downcase
		cdp = data["cdp"].downcase
		td = data["td"].downcase
		cr = data["cr"].downcase
		ir = data["ir"].downcase
		ar = data["ar"].downcase
	end

	# cvssV2
	if ac == "high"
	    cvss_ac = 0.35
	elsif ac == "medium"
	    cvss_ac = 0.61
	else
	    cvss_ac = 0.71
	end
	if au == "none"
	    cvss_au = 0.704
	elsif au == "single"
	    cvss_au = 0.56
	else
	    cvss_au = 0.45
	end
	if av == "local"
	    cvss_av = 0.395
	elsif av == "local network"
	    cvss_av = 0.646
	else
	    cvss_av = 1
	end
	if c == "none"
	    cvss_c = 0
	elsif c == "partial"
	    cvss_c = 0.275
	else
	    cvss_c = 0.660
	end
	if i == "none"
	    cvss_i = 00
	elsif i == "partial"
	    cvss_i = 0.275
	else
	    cvss_i = 0.660
	end
	if a == "none"
	    cvss_a = 0
	elsif a == "partial"
	    cvss_a = 0.275
	else
	    cvss_a = 0.660
	end

	# temporal score calculations
	if e == "unproven exploit exists"
	    cvss_e = 0.85
	elsif e == "proof-of-concept code"
	    cvss_e = 0.90
	elsif e == "functional exploit exists"
	    cvss_e = 0.95
	else
	    cvss_e = 1
	end
	if rl == "official fix"
	    cvss_rl = 0.87
	elsif rl == "temporary fix"
	    cvss_rl = 0.90
	elsif rl == "workaround"
	    cvss_rl = 0.95
	else
	    cvss_rl = 1
	end
	if rc == "unconfirmed"
	    cvss_rc = 0.90
	elsif rc == "uncorroborated"
	    cvss_rc = 0.95
	else
	    cvss_rc = 1
	end

	#environemental
	if cdp == "low"
	    cvss_cdp = 0.1
	elsif cdp == "low-medium"
	    cvss_cdp = 0.3
	elsif cdp == "medium-high"
	    cvss_cdp = 0.4
	elsif cdp == "high"
	    cvss_cdp = 0.5
	else
	    cvss_cdp = 0
	end
	if td == "none"
	    cvss_td = 0
	elsif td == "low"
	    cvss_td = 0.25
	elsif td == "medium"
	    cvss_td = 0.75
	else
	    cvss_td = 1
	end
	if cr == "low"
	    cvss_cr = 0.5
	elsif cr == "high"
	    cvss_cr = 1.51
	else
	    cvss_cr = 1
	end
	if ir == "low"
	    cvss_ir = 0.5
	elsif ir == "high"
	    cvss_ir = 1.51
	else
	    cvss_ir = 1
	end
	if ar == "low"
	    cvss_ar = 0.5
	elsif ar == "high"
	    cvss_ar = 1.51
	else
	    cvss_ar = 1
	end

	cvss_impact = 10.41 * (1 - (1 - cvss_c) * (1 - cvss_i) * (1 - cvss_a))
	cvss_exploitability = 20 * cvss_ac * cvss_au * cvss_av
	if cvss_impact == 0
	    cvss_impact_f = 0
	else
	    cvss_impact_f = 1.176
	end
	cvss_base = (0.6*cvss_impact + 0.4*cvss_exploitability-1.5)*cvss_impact_f
	cvss_temporal = cvss_base * cvss_e * cvss_rl * cvss_rc
	cvss_modified_impact = [10, 10.41 * (1 - (1 - cvss_c * cvss_cr) * (1 - cvss_i * cvss_ir) * (1 - cvss_a * cvss_ar))].min
	if cvss_modified_impact == 0
	    cvss_modified_impact_f = 0
	else
	    cvss_modified_impact_f = 1.176
	end
	cvss_modified_base = (0.6*cvss_modified_impact + 0.4*cvss_exploitability-1.5)*cvss_modified_impact_f
	cvss_adjusted_temporal = cvss_modified_base * cvss_e * cvss_rl * cvss_rc
	cvss_environmental = (cvss_adjusted_temporal + (10 - cvss_adjusted_temporal) * cvss_cdp) * cvss_td
	if cvss_environmental
	    cvss_total = cvss_environmental
	elsif cvss_temporal
	    cvss_total = cvss_temporal
	else
	    cvss_total = cvss_base
	end

	# cvssV3
	if is_cvssv3
		attack_vector = data["attack_vector"].downcase
		attack_complexity = data["attack_complexity"].downcase
		privileges_required = data["privileges_required"].downcase
		user_interaction = data["user_interaction"].downcase
		scope_cvss = data["scope_cvss"].downcase
		confidentiality = data["confidentiality"].downcase
		integrity = data["integrity"].downcase
		availability = data["availability"].downcase
		exploit_maturity = data["exploit_maturity"].downcase
		remeditation_level = data["remeditation_level"].downcase
		report_confidence = data["report_confidence"].downcase
		integrity_requirement = data["integrity_requirement"].downcase
		availability_requirement = data["availability_requirement"].downcase
		confidentiality_requirement = data["confidentiality_requirement"].downcase
		mod_attack_vector = data["mod_attack_vector"].downcase
		mod_attack_complexity = data["mod_attack_complexity"].downcase
		mod_privileges_required = data["mod_privileges_required"].downcase
		mod_user_interaction = data["mod_user_interaction"].downcase
		mod_scope = data["mod_scope"].downcase
		mod_confidentiality = data["mod_confidentiality"].downcase
		mod_integrity = data["mod_integrity"].downcase
		mod_availability = data["mod_availability"].downcase
 
	 	# Calculations taken from here:
	 	# https://gist.github.com/TheCjw/23b1f8b8f1da6ceb011c
	 	# https://www.first.org/cvss/specification-document#i8
	 
	 	#Base
	 	if confidentiality == "none"
	 		confidentiality_result = 0.0
	 	elsif confidentiality == "high"
	 		confidentiality_result = 0.56
	 	elsif confidentiality == "low"
	 		confidentiality_result = 0.22
	 	end

		if integrity == "none"
	 		integrity_result = 0.0
	 	elsif integrity == "high"
	 		integrity_result = 0.56
	 	elsif integrity == "low"
	 		integrity_result = 0.22
	 	end

	 	if availability == "none"
	 		availability_result = 0.0
	 	elsif availability == "high"
	 		availability_result = 0.56
	 	elsif availability == "low"
	 		availability_result = 0.22
	 	end

		if scope_cvss == "unchanged"
	 		scope_cvss_result = 6.42
	 	else
	 		scope_cvss_result = 7.52
	 	end

		if attack_vector == "network"
			attack_vector_result = 0.85
	 	elsif attack_vector == "adjacent"
	 		attack_vector_result = 0.62
	 	elsif attack_vector == "local"
	 		attack_vector_result = 0.55
	 	elsif attack_vector == "physical"
	 		attack_vector_result = 0.2
	 	end

	 	if attack_complexity == "high"
	 		attack_complexity_result = 0.44
	 	elsif attack_complexity == "low"
	 		attack_complexity_result = 0.77
	 	end

	 	if user_interaction == "none"
	 		user_interaction_result = 0.85
	 	elsif user_interaction == "required"
	 		user_interaction_result = 0.62
	 	end

		if privileges_required == "none"
	 		privileges_required_result = 0.85
	 	elsif privileges_required == "high"
	 		if (scope_cvss == "changed" || mod_scope == "changed")
	 			privileges_required_result = 0.50
	 		else
	 			privileges_required_result = 0.27
	 		end
	 	elsif privileges_required == "low"
	 		if (scope_cvss == "changed" || mod_scope == "changed")
	 			privileges_required_result = 0.68
	 		else
	 			privileges_required_result = 0.62
	 		end
	 	end

		#Temporal
	 	if exploit_maturity == "not defined"
	 		exploit_maturity_result = 1
	 	elsif exploit_maturity == "high"
	 		exploit_maturity_result = 1
	 	elsif exploit_maturity == "functional exploit exists"
	 		exploit_maturity_result = 0.97
	 	elsif exploit_maturity == "proof-of-concept code"
	 		exploit_maturity_result = 0.94
	 	elsif exploit_maturity == "unproven exploit exists"
	 		exploit_maturity_result = 0.91
	 	end

	 	if remeditation_level == "not defined"
	 		remeditation_level_result = 1
	 	elsif remeditation_level == "unavailable"
	 		remeditation_level_result = 1
	 	elsif remeditation_level == "workaround"
	 		remeditation_level_result = 0.97
	 	elsif remeditation_level == "temporary fix"
	 		remeditation_level_result = 0.96
	 	elsif remeditation_level == "official fix"
	 		remeditation_level_result = 0.95
	 	end

		if report_confidence == "not defined"
	 		report_confidence_result = 1
	 	elsif report_confidence == "confirmed"
	 		report_confidence_result = 1
	 	elsif report_confidence == "reasonable"
	 		report_confidence_result = 0.96
	 	elsif report_confidence == "unknown"
	 		report_confidence_result = 0.92
	 	end

	 	#Enviromental
	 	if confidentiality_requirement == "not defined"
	 		confidentiality_requirement_result = 1
	 	elsif confidentiality_requirement == "high"
	 		confidentiality_requirement_result = 1.5
	 	elsif confidentiality_requirement == "medium"
	 		confidentiality_requirement_result = 1
	 	elsif confidentiality_requirement == "low"
	 		confidentiality_requirement_result = 0.5
	 	end

	 	if integrity_requirement == "not defined"
	 		integrity_requirement_result = 1
	 	elsif integrity_requirement == "high"
	 		integrity_requirement_result = 1.5
	 	elsif integrity_requirement == "medium"
	 		integrity_requirement_result = 1
	 	elsif integrity_requirement == "low"
	 		integrity_requirement_result = 0.5
	 	end

	 	if availability_requirement == "not defined"
	 		availability_requirement_result = 1
	 	elsif availability_requirement == "high"
	 		availability_requirement_result = 1.5
	 	elsif availability_requirement == "medium"
	 		availability_requirement_result = 1
	 	elsif availability_requirement == "low"
	 		availability_requirement_result = 0.5
	 	end
	 	
	 	if mod_confidentiality == "none"
	 		mod_confidentiality_result = 0.0
	 	elsif mod_confidentiality == "high"
	 		mod_confidentiality_result = 0.56
	 	elsif mod_confidentiality == "low"
	 		mod_confidentiality_result = 0.22
	 	elsif mod_confidentiality == "not defined"
	 		mod_confidentiality_result = confidentiality_result
	 	end


	 	if mod_integrity == "none"
	 		mod_integrity_result = 0.0
	 	elsif mod_integrity == "high"
	 		mod_integrity_result = 0.56
	 	elsif mod_integrity == "low"
	 		mod_integrity_result = 0.22
	 	elsif mod_integrity == "not defined"
	 		mod_integrity_result = integrity_result
	 	end

		if mod_availability == "none"
	 		mod_availability_result = 0.0
	 	elsif mod_availability == "high"
	 		mod_availability_result = 0.56
	 	elsif mod_availability == "low"
	 		mod_availability_result = 0.22
	 	elsif mod_availability == "not defined"
	 		mod_availability_result = availability_result
	 	end

	 	if mod_scope == "unchanged"
	 		mod_scope_result = 6.42
	 	elsif mod_scope == "changed"
	 		mod_scope_result = 7.52
	 	elsif mod_scope == "not defined"
	 		mod_scope_result = scope_cvss_result
	 	end

		if mod_attack_vector == "network"
	 		mod_attack_vector_result = 0.85
	 	elsif mod_attack_vector == "adjacent"
	 		mod_attack_vector_result = 0.62
	 	elsif mod_attack_vector == "local"
	 		mod_attack_vector_result = 0.55
	 	elsif mod_attack_vector == "physical"
	 		mod_attack_vector_result = 0.2
	 	elsif mod_attack_vector == "not defined"
	 		mod_attack_vector_result = attack_vector_result
	 	end
	 
	 	if mod_attack_complexity == "high"
	 		mod_attack_complexity_result = 0.44
	 	elsif mod_attack_complexity == "low"
	 		mod_attack_complexity_result = 0.77
	 	elsif mod_attack_complexity == "not defined"
	 		mod_attack_complexity_result = attack_complexity_result
	 	end

	 	if mod_user_interaction == "none"
	 		mod_user_interaction_result = 0.85
	 	elsif mod_user_interaction == "required"
	 		mod_user_interaction_result = 0.62
	 	elsif mod_user_interaction == "not defined"
	 		mod_user_interaction_result = user_interaction_result
	 	end
	 
	 	if mod_privileges_required == "none"
	 		mod_privileges_required_result = 0.85
	 	elsif mod_privileges_required == "low"
	 		if (scope_cvss == "changed" || mod_scope == "changed")
	 			mod_privileges_required_result = 0.68
	 		else
	 			mod_privileges_required_result = 0.62
	 		end
	 	elsif mod_privileges_required == "high"
	 		if (scope_cvss == "changed" || mod_scope == "changed")
	 			mod_privileges_required_result = 0.5
	 		else
	 			mod_privileges_required_result = 0.27
	 		end
	 	elsif mod_privileges_required == "not defined"
	 		mod_privileges_required_result = privileges_required_result
	 	end

		# Base Score
	 	cvss_exploitability = 8.22 * attack_vector_result * attack_complexity_result * privileges_required_result * user_interaction_result #exploitabilitySubScore
	 	cvss_impact_multipler = (1 - ((1 - confidentiality_result) * (1 - integrity_result) * (1 - availability_result))) # ISCbase
	 	
	 	if scope_cvss == "unchanged"
	 		cvss_impact_score = scope_cvss_result * cvss_impact_multipler
	 	elsif scope_cvss == "changed"
	 		cvss_impact_score = scope_cvss_result * (cvss_impact_multipler - 0.029) - 3.25 * ((cvss_impact_multipler - 0.02) ** 15)
	 	end

		if cvss_impact_score <= 0
			cvss_base_score = 0
		end

		if scope_cvss == "unchanged"
	 		if (cvss_exploitability + cvss_impact_score) < 10
	 			cvss_base_score = (((cvss_exploitability + cvss_impact_score) * 10).ceil) / 10.0
	 		else
	 			cvss_base_score = 10
	 		end	
		elsif scope_cvss == "changed"
			if ((cvss_exploitability + cvss_impact_score) * 1.08) < 10
				cvss_base_score = ((((cvss_exploitability + cvss_impact_score) * 1.08) * 10).ceil) / 10.0
			else
				cvss_base_score = 10
			end
	 	end
	 	cvss_base_score = ((cvss_base_score * 10).ceil) / 10.0

		# Temporal Score
	 	cvss_temporal = ((cvss_base_score * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil) / 10.0

		# Enviromental Score
	 	cvss_mod_exploitability = 8.22 * mod_attack_vector_result * mod_attack_complexity_result * mod_privileges_required_result * mod_user_interaction_result
	 
	 	if (1 - (1 - mod_confidentiality_result * confidentiality_requirement_result) * (1 - mod_integrity_result * integrity_requirement_result) * (1 - mod_availability_result * availability_requirement_result)) > 0.915
	 		cvss_mod_impact_multipler = 0.915
	 	end

		cvss_mod_impact_multipler = 1 - (1 - mod_confidentiality_result * confidentiality_requirement_result) * (1 - mod_integrity_result * integrity_requirement_result) * (1 - mod_availability_result * availability_requirement_result)


		if mod_scope == "unchanged"
	 		cvss_mod_impact_score = mod_scope_result * cvss_mod_impact_multipler
	 	elsif mod_scope == "changed"
	 		cvss_mod_impact_score = mod_scope_result * (cvss_mod_impact_multipler - 0.029) - 3.25 * ((cvss_mod_impact_multipler - 0.02) ** 15)
	 	elsif mod_scope == "not defined"
	 		if scope_cvss == "unchanged"
	 			cvss_mod_impact_score = scope_cvss_result * cvss_mod_impact_multipler
	 		elsif scope_cvss =="changed"
	 			cvss_mod_impact_score = scope_cvss_result * (cvss_mod_impact_multipler - 0.029) - 3.25 * ((cvss_mod_impact_multipler - 0.02) ** 15)
	 		end
	 	end
	 
	 	mod_impact_exploit_add = cvss_mod_impact_score + cvss_mod_exploitability
	 
	 	if cvss_mod_impact_score <= 0
	 		cvss_environmental = 0
	 	else
	 		if mod_scope == "not defined"
	 			if scope_cvss == "unchanged"
	 				if mod_impact_exploit_add > 10
	 					mod_impact_exploit_add = 10
	 				else
	 					mod_impact_exploit_add = ((mod_impact_exploit_add * 10).ceil) / 10.0
	 				end
	 				cvss_environmental = ((mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil) / 10.0
	 			elsif scope_cvss == "changed"
	 				if (((1.08 * mod_impact_exploit_add * 10).ceil) / 10.0) > 10
	 					mod_impact_exploit_add = 10
	 				else
	 					mod_impact_exploit_add = ((1.08 * mod_impact_exploit_add * 10).ceil) / 10.0
	 				end
	 				cvss_environmental = ((mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil) / 10.0
	 			end
	 		end
	 		if mod_scope == "unchanged"
	 			if mod_impact_exploit_add > 10
	 				mod_impact_exploit_add = 10
	 			else
	 				mod_impact_exploit_add = ((mod_impact_exploit_add * 10).ceil) / 10.0
	 			end
	 			cvss_environmental = ((mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil) / 10.0
	 		elsif mod_scope == "changed"
	 			if (((1.08 * mod_impact_exploit_add * 10).ceil) / 10.0) > 10
	 				mod_impact_exploit_add = 10
	 			else
	 				mod_impact_exploit_add = ((1.08 * mod_impact_exploit_add * 10).ceil) / 10.0
	 			end
	 			cvss_environmental = ((mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil) / 10.0
	 		end
	 	end
	end

	data["cvss_base"] = sprintf("%0.1f" % cvss_base)
	data["cvss_impact"] = sprintf("%0.1f" % cvss_impact)
	data["cvss_exploitability"] = sprintf("%0.1f" % cvss_exploitability)
	data["cvss_temporal"] = sprintf("%0.1f" % cvss_temporal)
	data["cvss_environmental"] = sprintf("%0.1f" % cvss_environmental)
	data["cvss_modified_impact"] = sprintf("%0.1f" % cvss_modified_impact)

	if(is_cvssv3)
		data["cvss_base_score"] = sprintf("%0.1f" % cvss_base_score)
 		data["cvss_impact_score"] = sprintf("%0.1f" % cvss_impact_score)	
		data["cvss_mod_impact_score"] = sprintf("%0.1f" % cvss_mod_impact_score)
	
	 	data["cvss_total"] = sprintf("%0.1f" % cvss_environmental)
	else
		data["cvss_total"] = sprintf("%0.1f" % cvss_total)
	end

	return data
end

# there are three scoring types; risk, dread and cvss
#    this sets a score for all three in case the user switches later

def convert_score(finding)
	if(finding.cvss_total == nil)
		puts "|!| No CVSS score exists"
		finding.cvss_total = 0
	end
	if(finding.dread_total == nil)
		puts "|!| No DREAD score exists"
		finding.dread_total = 0
	end
	if(finding.risk == nil)
		puts "|!| No RISK score exists"
		finding.risk = 0
	end
	return finding
end

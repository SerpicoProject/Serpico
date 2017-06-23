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
    if report.user_defined_variables
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
def cvss(data)
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
	else
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
	end
	
	cvss_base_score = ((cvss_base_score * 10).ceil) / 10.0

	# Temporal Score
	cvss_temporal = ((cvss_base_score * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil) / 10.0

	# Enviromental Score
	cvss_mod_exploitability = 8.22 * mod_attack_vector_result * mod_attack_complexity_result * mod_privileges_required_result * mod_user_interaction_result

	if (1 - (1 - mod_confidentiality_result * confidentiality_requirement_result) * (1 - mod_integrity_result * integrity_requirement_result) * (1 - mod_availability_result * availability_requirement_result)) > 0.915
		cvss_mod_impact_multipler = 0.915
	else
		cvss_mod_impact_multipler = 1 - (1 - mod_confidentiality_result * confidentiality_requirement_result) * (1 - mod_integrity_result * integrity_requirement_result) * (1 - mod_availability_result * availability_requirement_result)
	end

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

	data["cvss_base_score"] = sprintf("%0.1f" % cvss_base_score)
	data["cvss_impact_score"] = sprintf("%0.1f" % cvss_impact_score)
	data["cvss_exploitability"] = sprintf("%0.1f" % cvss_exploitability)
	data["cvss_temporal"] = sprintf("%0.1f" % cvss_temporal)
	data["cvss_environmental"] = sprintf("%0.1f" % cvss_environmental)
	data["cvss_mod_impact_score"] = sprintf("%0.1f" % cvss_mod_impact_score)
	data["cvss_total"] = sprintf("%0.1f" % cvss_environmental)

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
		puts "|!| No CVSS score exists"
		finding.dread_total = 0
	end
	if(finding.risk == nil)
		puts "|!| No CVSS score exists"
		finding.risk = 0
	end
	return finding
end

require 'rubygems'

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
		elsif k == "remediation" or k == "overview" or k == "poc" or k == "affected_hosts"
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

def meta_markup_unencode(findings_xml, customer_name)

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

  # changes the <<CUSTOMER>> marks
  if customer_name
	  findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;CUSTOMER&amp;gt;&amp;gt;","#{customer_name}")
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


	data["cvss_base"] = sprintf("%0.1f" % cvss_base)
	data["cvss_impact"] = sprintf("%0.1f" % cvss_impact)
	data["cvss_exploitability"] = sprintf("%0.1f" % cvss_exploitability)
	data["cvss_temporal"] = sprintf("%0.1f" % cvss_temporal)
	data["cvss_environmental"] = sprintf("%0.1f" % cvss_environmental)
	data["cvss_modified_impact"] = sprintf("%0.1f" % cvss_modified_impact)
	data["cvss_total"] = sprintf("%0.1f" % cvss_total)

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
